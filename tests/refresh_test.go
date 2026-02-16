package tests

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/deifyed/mini-auth/miniauth"
)

func TestRefresh(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		useValidRefreshToken bool
		expectedStatus       int
		expectNewTokens      bool
	}{
		"valid refresh token issues new tokens": {
			useValidRefreshToken: true,
			expectedStatus:       http.StatusOK,
			expectNewTokens:      true,
		},
		"invalid refresh token returns 401": {
			useValidRefreshToken: false,
			expectedStatus:       http.StatusUnauthorized,
			expectNewTokens:      false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Create setup with very short access token TTL
			setup := newShortTTLTestSetup(t, 1*time.Millisecond)
			defer setup.Close()

			client := &http.Client{}

			// Login to get tokens
			loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
			cookies := getCookies(loginResp)
			loginResp.Body.Close()

			refreshCookie := findCookie(cookies, "refresh_token")
			if refreshCookie == nil {
				t.Fatal("expected refresh_token cookie")
			}

			// Wait for access token to expire
			time.Sleep(10 * time.Millisecond)

			// Make request with only refresh token (simulating expired access token)
			req, _ := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)

			if tc.useValidRefreshToken {
				req.AddCookie(refreshCookie)
			} else {
				req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "invalid-token"})
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("failed to do request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}

			if tc.expectNewTokens {
				newCookies := getCookies(resp)
				newAccessCookie := findCookie(newCookies, "access_token")

				if newAccessCookie == nil {
					t.Error("expected new access_token cookie")
				}
			}
		})
	}
}

func TestRefreshTokenRemainsValid(t *testing.T) {
	t.Parallel()

	// Create setup with very short access token TTL
	setup := newShortTTLTestSetup(t, 1*time.Millisecond)
	defer setup.Close()

	client := &http.Client{}

	// Login to get initial tokens
	loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	cookies := getCookies(loginResp)
	loginResp.Body.Close()

	refreshCookie := findCookie(cookies, "refresh_token")
	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie")
	}

	// Wait for access token to expire
	time.Sleep(10 * time.Millisecond)

	// The same refresh token should work across multiple refreshes
	for i := range 3 {
		req, _ := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
		req.AddCookie(refreshCookie)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: failed to do request: %v", i, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, resp.StatusCode)
		}

		// Wait for the new access token to expire before next iteration
		time.Sleep(10 * time.Millisecond)
	}
}

// newShortTTLTestSetup creates a test setup with a configurable access token TTL.
func newShortTTLTestSetup(t *testing.T, accessTTL time.Duration) *testSetup {
	t.Helper()

	// Create temp DB
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db := &miniauth.Sqlite3{Path: dbPath}
	if err := db.Init(); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	// Create test user
	_, err := db.CreateUser(testUsername, testPassword)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// Create middleware with short access TTL
	middleware := &miniauth.Middleware{
		Datastore: db,
		Secret:    []byte(testSecret),
		AccessTTL: accessTTL,
		Insecure:  true,
	}

	// Create mux with routes
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", miniauth.Login(middleware))
	mux.HandleFunc("POST /logout", miniauth.Logout(middleware))
	mux.Handle("GET /protected", middleware.Wrap(http.HandlerFunc(protectedHandler)))

	server := httptest.NewServer(mux)

	return &testSetup{
		Server:     server,
		Middleware: middleware,
		DB:         db,
		dbPath:     dbPath,
	}
}
