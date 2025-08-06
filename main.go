// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

// Config holds the application configuration.
// We get these from environment variables.
type Config struct {
	TeamDomain    string // Your Cloudflare Access team domain
	AudienceTag   string // The Application Audience (AUD) tag
	ListenAddress string // The address and port to listen on
}

// KeySet holds the fetched JWKs from Cloudflare.
// It includes a cache mechanism to avoid fetching on every request.
type KeySet struct {
	jwks      jwk.Set
	fetchURL  string
	lastFetch time.Time
	maxAge    time.Duration
}

// newKeySet initializes a KeySet.
func newKeySet(teamDomain string) *KeySet {
	return &KeySet{
		fetchURL:  fmt.Sprintf("https://%s.cloudflareaccess.com/cdn-cgi/access/certs", teamDomain),
		maxAge:    24 * time.Hour, // As per Cloudflare docs, keys rotate every 24h
		lastFetch: time.Time{},    // Zero time ensures the first fetch happens
	}
}

// fetchKeys retrieves the public keys from Cloudflare Access and caches them.
func (k *KeySet) fetchKeys(ctx context.Context) (jwk.Set, error) {
	// Use cache if it's not older than maxAge
	if time.Since(k.lastFetch) < k.maxAge && k.jwks != nil {
		log.Println("Using cached JWK set.")
		return k.jwks, nil
	}

	log.Println("Fetching new JWK set from:", k.fetchURL)
	jwks, err := jwk.Fetch(ctx, k.fetchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKs: %w", err)
	}

	// Update cache
	k.jwks = jwks
	k.lastFetch = time.Now()

	return jwks, nil
}

// validationHandler is the HTTP handler for NGINX's auth_request.
func (app *application) validationHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Extract the token from the CF_Authorization cookie
	cookie, err := r.Cookie("CF_Authorization")
	if err != nil {
		log.Println("Validation failed: Missing CF_Authorization cookie")
		http.Error(w, "Missing CF_Authorization cookie", http.StatusUnauthorized)
		return
	}
	jwtB64 := cookie.Value

	// 2. Fetch the JWK set from Cloudflare
	jwks, err := app.keySet.fetchKeys(r.Context())
	if err != nil {
		log.Printf("ERROR: Could not fetch JWKs: %v", err)
		http.Error(w, "Failed to fetch validation keys", http.StatusInternalServerError)
		return
	}

	// 3. Parse and validate the token
	token, err := jwt.Parse(jwtB64, func(token *jwt.Token) (interface{}, error) {
		// Find the key that matches the 'kid' in the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("expected 'kid' header field")
		}

		key, found := jwks.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("unable to find key with kid '%s'", kid)
		}

		// Get the raw public key to be used for validation
		var pubKey interface{}
		if err := key.Raw(&pubKey); err != nil {
			return nil, fmt.Errorf("failed to get raw public key: %w", err)
		}

		return pubKey, nil
	})

	if err != nil {
		log.Printf("Validation failed: Invalid token: %v", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 4. Check if the token is valid and verify claims
	if !token.Valid {
		log.Println("Validation failed: Token is not valid")
		http.Error(w, "Token is not valid", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("Validation failed: Could not parse token claims")
		http.Error(w, "Could not parse token claims", http.StatusUnauthorized)
		return
	}

	// Verify 'aud' (Audience) claim
	if !claims.VerifyAudience(app.config.AudienceTag, true) {
		log.Printf("Validation failed: Invalid 'aud' claim. Expected '%s', got '%v'", app.config.AudienceTag, claims["aud"])
		http.Error(w, "Invalid audience", http.StatusUnauthorized)
		return
	}

	// Verify 'iss' (Issuer) claim
	expectedIssuer := fmt.Sprintf("https://%s.cloudflareaccess.com", app.config.TeamDomain)
	if !claims.VerifyIssuer(expectedIssuer, true) {
		log.Printf("Validation failed: Invalid 'iss' claim. Expected '%s', got '%v'", expectedIssuer, claims["iss"])
		http.Error(w, "Invalid issuer", http.StatusUnauthorized)
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
	log.Println("Validation successful for user:", claims["email"])
	cfEmail := fmt.Sprintf("%v", claims["email"])
	w.Header().Add("x-authentication-id", cfEmail)
	w.WriteHeader(http.StatusOK)
}

// application struct to hold dependencies
type application struct {
	config *Config
	keySet *KeySet
}

func main() {
	// Load configuration from environment variables
	cfg := &Config{
		TeamDomain:    os.Getenv("CF_TEAM_DOMAIN"),
		AudienceTag:   os.Getenv("CF_AUDIENCE_TAG"),
		ListenAddress: ":9001",
	}

	if cfg.TeamDomain == "" || cfg.AudienceTag == "" {
		log.Fatal("FATAL: Environment variables CF_TEAM_DOMAIN and CF_AUDIENCE_TAG must be set.")
	}

	app := &application{
		config: cfg,
		keySet: newKeySet(cfg.TeamDomain),
	}

	// Pre-fetch keys on startup to ensure they are available.
	if _, err := app.keySet.fetchKeys(context.Background()); err != nil {
		log.Printf("WARNING: Could not pre-fetch JWKs on startup: %v", err)
	}

	// Define the HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.validationHandler) // NGINX will send all subrequests here

	log.Printf("Starting JWT validation service on %s", cfg.ListenAddress)
	log.Printf("Configured for Team Domain: %s", cfg.TeamDomain)
	log.Printf("Configured for Audience Tag: %s", cfg.AudienceTag)

	// Start the server
	if err := http.ListenAndServe(cfg.ListenAddress, mux); err != nil {
		log.Fatalf("FATAL: Could not start server: %s\n", err)
	}
}
