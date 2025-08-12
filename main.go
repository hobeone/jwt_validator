// main.go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Config holds the application configuration.
// We get these from environment variables.
type Config struct {
	TeamDomain    string `envconfig:"CF_TEAM_DOMAIN" required:"true"`
	AudienceTag   string `envconfig:"CF_AUDIENCE_TAG" required:"true"`
	ListenAddress string `envconfig:"LISTEN_ADDRESS" default:":9001"`
}

// validate performs basic sanity checks on configuration values.
func (c *Config) validate() error {
	// Restrict team domain to alphanumerics and hyphen to avoid SSRF/host injection
	domainPattern := regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	if !domainPattern.MatchString(c.TeamDomain) {
		return fmt.Errorf("invalid CF_TEAM_DOMAIN: %q", c.TeamDomain)
	}
	if c.AudienceTag == "" {
		return fmt.Errorf("CF_AUDIENCE_TAG must not be empty")
	}
	return nil
}

// KeySet holds the fetched JWKs from Cloudflare.
// It includes a cache mechanism to avoid fetching on every request.
type KeySet struct {
	jwks      jwk.Set
	fetchURL  string
	lastFetch time.Time
	maxAge    time.Duration
	mu        sync.RWMutex
	client    *http.Client
}

// newKeySet initializes a KeySet.
func newKeySet(teamDomain string) *KeySet {
	return &KeySet{
		fetchURL:  fmt.Sprintf("https://%s.cloudflareaccess.com/cdn-cgi/access/certs", teamDomain),
		maxAge:    24 * time.Hour, // As per Cloudflare docs, keys rotate every 24h
		lastFetch: time.Time{},    // Zero time ensures the first fetch happens
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// fetchKeys retrieves the public keys from Cloudflare Access and caches them.
func (k *KeySet) fetchKeys(ctx context.Context) (jwk.Set, error) {
	// Use cache if it's not older than maxAge
	k.mu.RLock()
	if time.Since(k.lastFetch) < k.maxAge && k.jwks != nil {
		jwks := k.jwks
		k.mu.RUnlock()
		slog.Debug("Using cached JWK set.")
		return jwks, nil
	}
	k.mu.RUnlock()

	slog.Info("Fetching new JWK set from", "url", k.fetchURL)
	jwks, err := jwk.Fetch(ctx, k.fetchURL, jwk.WithHTTPClient(k.client))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKs: %w", err)
	}

	// Update cache
	k.mu.Lock()
	k.jwks = jwks
	k.lastFetch = time.Now()
	k.mu.Unlock()

	return jwks, nil
}

// validationHandler is the HTTP handler for NGINX's auth_request.
func (app *application) validationHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Extract the token from the CF_Authorization cookie
	cookie, err := r.Cookie("CF_Authorization")
	if err != nil {
		slog.Warn("Validation failed: Missing CF_Authorization cookie")
		http.Error(w, "Missing CF_Authorization cookie", http.StatusUnauthorized)
		return
	}
	jwtB64 := cookie.Value

	// 2. Fetch the JWK set from Cloudflare
	jwks, err := app.keySet.fetchKeys(r.Context())
	if err != nil {
		slog.Error("Could not fetch JWKs", "error", err)
		http.Error(w, "Failed to fetch validation keys", http.StatusInternalServerError)
		return
	}

	// 3. Parse and validate the token
	token, err := jwt.Parse([]byte(jwtB64), jwt.WithKeySet(jwks))
	if err != nil {
		slog.Warn("Validation failed: Invalid token", "error", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 4. Verify claims
	expectedIssuer := fmt.Sprintf("https://%s.cloudflareaccess.com", app.config.TeamDomain)
	err = jwt.Validate(token,
		jwt.WithIssuer(expectedIssuer),
		jwt.WithAudience(app.config.AudienceTag),
	)
	if err != nil {
		slog.Warn("Validation failed: Invalid claims", "error", err)
		http.Error(w, "Invalid claims", http.StatusUnauthorized)
		return
	}

	// Require 'email' claim for downstream auth propagation
	var cfEmail string
	err = token.Get("email", &cfEmail)
	if err != nil {
		slog.Warn("Validation failed: Missing 'email' claim")
		http.Error(w, "Missing required claim", http.StatusUnauthorized)
		return
	}
	if cfEmail == "" {
		slog.Warn("Validation failed: 'email' claim is an empty string")
		http.Error(w, "Invalid email claim", http.StatusUnauthorized)
		return
	}

	// 5. If all checks pass, return 200 OK
	// Include the claim email in the x-authentication-id header of the response
	// Nginx can grab this with the auth_request_set directive.
	//
	// i.e. for Grafana auth.proxy usage:
	// auth_request_set $x_authentication_id $sent_http_x_authentication_id;
	// proxy_set_header X-WEBAUTH-USER $x_authentication_id;
	// proxy_pass         http://grafana;
	slog.Info("Validation successful", "email", cfEmail)
	w.Header().Add("x-authentication-id", cfEmail)
	w.WriteHeader(http.StatusOK)
}

// application struct to hold dependencies
type application struct {
	config *Config
	keySet *KeySet
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load configuration from environment variables
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		slog.Error("FATAL: Could not process configuration", "error", err)
		os.Exit(1)
	}

	if err := cfg.validate(); err != nil {
		slog.Error("FATAL: Invalid configuration", "error", err)
		os.Exit(1)
	}

	app := &application{
		config: &cfg,
		keySet: newKeySet(cfg.TeamDomain),
	}

	// Pre-fetch keys on startup to ensure they are available.
	if _, err := app.keySet.fetchKeys(context.Background()); err != nil {
		slog.Warn("Could not pre-fetch JWKs on startup", "error", err)
	}

	// Define the HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", app.validationHandler)

	slog.Info("Built with GO", "version", runtime.Version())
	slog.Info("Starting JWT validation service", "address", cfg.ListenAddress)
	slog.Info("Configured for Team Domain", "domain", cfg.TeamDomain)
	slog.Info("Configured for Audience Tag", "tag", cfg.AudienceTag)

	// Start the server with timeouts to mitigate slowloris and resource exhaustion
	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		slog.Error("FATAL: Could not start server", "error", err)
		os.Exit(1)
	}
}
