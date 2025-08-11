// main_test.go
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

// generateTestKeys creates a new RSA private key and a corresponding JWK public key for testing.
func generateTestKeys() (*rsa.PrivateKey, jwk.Key, error) {
	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Create a JWK from the public part of the RSA key
	publicKey, err := jwk.New(privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create JWK from public key: %w", err)
	}

	// Set the Key ID, which is crucial for lookup
	if err := publicKey.Set(jwk.KeyIDKey, "test-kid"); err != nil {
		return nil, nil, fmt.Errorf("failed to set kid on JWK: %w", err)
	}

	// Set the algorithm
	if err := publicKey.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return nil, nil, fmt.Errorf("failed to set alg on JWK: %w", err)
	}

	return privateKey, publicKey, nil
}

// createTestToken generates a signed JWT string for testing purposes.
func createTestToken(privateKey *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-kid"

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return signedToken, nil
}

// TestValidationHandler runs table-driven tests on the validationHandler.
func TestValidationHandler(t *testing.T) {
	// 1. Setup: Generate keys and a mock JWKS endpoint
	privateKey, publicKey, err := generateTestKeys()
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}

	// Create a mock server to act as the Cloudflare JWKS endpoint
	mockJwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keySet := jwk.NewSet()
		keySet.Add(publicKey)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(keySet); err != nil {
			t.Fatalf("Failed to encode mock JWKS response: %v", err)
		}
	}))
	defer mockJwksServer.Close()

	// 2. Setup: Create the application instance for testing
    testConfig := &Config{
        TeamDomain:    "test-team",
        AudienceTag:   "test-aud-tag",
        ListenAddress: ":9001",
    }

	// We override the fetchURL to point to our mock server
    testKeySet := newKeySet(testConfig.TeamDomain)
	testKeySet.fetchURL = mockJwksServer.URL

	app := &application{
		config: testConfig,
		keySet: testKeySet,
	}

	// 3. Define Test Cases
	testCases := []struct {
		name               string
		buildRequest       func() *http.Request
		expectedStatusCode int
	}{
        {
			name: "Valid Token",
			buildRequest: func() *http.Request {
				claims := jwt.MapClaims{
					"aud": "test-aud-tag",
					"iss": "https://test-team.cloudflareaccess.com",
					"exp": time.Now().Add(time.Hour).Unix(),
					"iat": time.Now().Unix(),
                    "email": "user@example.com",
				}
				token, _ := createTestToken(privateKey, claims)
				req, _ := http.NewRequest("GET", "/", nil)
                req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: token})
				return req
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "Missing Authorization Cookie",
			buildRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
        {
			name: "Invalid Signature",
			buildRequest: func() *http.Request {
				// Sign with a different key
				otherPrivateKey, _, _ := generateTestKeys()
				claims := jwt.MapClaims{
					"aud": "test-aud-tag",
					"iss": "https://test-team.cloudflareaccess.com",
                    "email": "user@example.com",
				}
				token, _ := createTestToken(otherPrivateKey, claims)
				req, _ := http.NewRequest("GET", "/", nil)
				req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: token})
				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
        {
			name: "Invalid Audience (aud)",
			buildRequest: func() *http.Request {
				claims := jwt.MapClaims{
					"aud": "wrong-aud-tag",
					"iss": "https://test-team.cloudflareaccess.com",
                    "email": "user@example.com",
				}
				token, _ := createTestToken(privateKey, claims)
				req, _ := http.NewRequest("GET", "/", nil)
				req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: token})
				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
        {
			name: "Invalid Issuer (iss)",
			buildRequest: func() *http.Request {
				claims := jwt.MapClaims{
					"aud": "test-aud-tag",
					"iss": "https://wrong-team.cloudflareaccess.com",
                    "email": "user@example.com",
				}
				token, _ := createTestToken(privateKey, claims)
				req, _ := http.NewRequest("GET", "/", nil)
				req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: token})
				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
        {
			name: "Expired Token",
			buildRequest: func() *http.Request {
				claims := jwt.MapClaims{
					"aud": "test-aud-tag",
					"iss": "https://test-team.cloudflareaccess.com",
					"exp": time.Now().Add(-time.Hour).Unix(), // Expired one hour ago
                    "email": "user@example.com",
				}
				token, _ := createTestToken(privateKey, claims)
				req, _ := http.NewRequest("GET", "/", nil)
				req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: token})
				return req
			},
			expectedStatusCode: http.StatusUnauthorized,
		},
        {
            name: "Missing Email Claim",
            buildRequest: func() *http.Request {
                claims := jwt.MapClaims{
                    "aud": "test-aud-tag",
                    "iss": "https://test-team.cloudflareaccess.com",
                    "exp": time.Now().Add(time.Hour).Unix(),
                    "iat": time.Now().Unix(),
                }
                token, _ := createTestToken(privateKey, claims)
                req, _ := http.NewRequest("GET", "/", nil)
                req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: token})
                return req
            },
            expectedStatusCode: http.StatusUnauthorized,
        },
        {
            name: "Reject HS256 Token",
            buildRequest: func() *http.Request {
                // Build an HS256 token that would otherwise be valid; it should be rejected
                hsToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
                    "aud": "test-aud-tag",
                    "iss": "https://test-team.cloudflareaccess.com",
                    "exp": time.Now().Add(time.Hour).Unix(),
                    "email": "user@example.com",
                })
                hsToken.Header["kid"] = "test-kid"
                signed, _ := hsToken.SignedString([]byte("secret"))
                req, _ := http.NewRequest("GET", "/", nil)
                req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: signed})
                return req
            },
            expectedStatusCode: http.StatusUnauthorized,
        },
	}

	// 4. Run Tests
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// In case a test closes the server, we need to reset it for the next one
			if mockJwksServer.URL == "" {
				mockJwksServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					keySet := jwk.NewSet()
					keySet.Add(publicKey)
					json.NewEncoder(w).Encode(keySet)
				}))
				app.keySet.fetchURL = mockJwksServer.URL
				// Clear the cache to force a re-fetch
				app.keySet.lastFetch = time.Time{}
			}

			req := tc.buildRequest()
			rr := httptest.NewRecorder()
            handler := http.HandlerFunc(app.validationHandler)

            handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tc.expectedStatusCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tc.expectedStatusCode)
				t.Errorf("response body: %s", rr.Body.String())
			}
		})
	}
}

// We need to suppress the output from the main application's logger during tests
func init() {
	log.SetOutput(&nullWriter{})
}

type nullWriter struct{}

func (w *nullWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func TestFetchKeysCache(t *testing.T) {
	// 1. Setup: Generate keys and a mock JWKS endpoint
	_, publicKey, err := generateTestKeys()
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}

	// Create a mock server to act as the Cloudflare JWKS endpoint
	var fetchCount int
	mockJwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		keySet := jwk.NewSet()
		keySet.Add(publicKey)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(keySet); err != nil {
			t.Fatalf("Failed to encode mock JWKS response: %v", err)
		}
	}))
	defer mockJwksServer.Close()

	// 2. Setup: Create the application instance for testing
	testConfig := &Config{
		TeamDomain: "test-team",
	}

	// We override the fetchURL to point to our mock server
	testKeySet := newKeySet(testConfig.TeamDomain)
	testKeySet.fetchURL = mockJwksServer.URL
	testKeySet.maxAge = 1 * time.Hour // Set a long cache duration for the first part of the test

	// 3. First fetch - should fetch from the server
	_, err = testKeySet.fetchKeys(context.Background())
	if err != nil {
		t.Fatalf("First fetch failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("Expected 1 fetch, got %d", fetchCount)
	}
	firstFetchTime := testKeySet.lastFetch

	// 4. Second fetch - should use the cache
	_, err = testKeySet.fetchKeys(context.Background())
	if err != nil {
		t.Fatalf("Second fetch failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("Expected 1 fetch after cached call, got %d", fetchCount)
	}
	if !testKeySet.lastFetch.Equal(firstFetchTime) {
		t.Errorf("Expected lastFetch time to be unchanged, but it was updated")
	}

	// 5. Expire the cache and fetch again
	testKeySet.maxAge = 1 * time.Nanosecond // Expire the cache
	time.Sleep(2 * time.Nanosecond)

	_, err = testKeySet.fetchKeys(context.Background())
	if err != nil {
		t.Fatalf("Third fetch failed: %v", err)
	}
	if fetchCount != 2 {
		t.Errorf("Expected 2 fetches after cache expiration, got %d", fetchCount)
	}
	if testKeySet.lastFetch.Equal(firstFetchTime) {
		t.Errorf("Expected lastFetch time to be updated, but it was unchanged")
	}
}