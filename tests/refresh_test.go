package tests

import (
	"net/http"
	"net/http/httptest"
	"os"
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
				newRefreshCookie := findCookie(newCookies, "refresh_token")

				if newAccessCookie == nil {
					t.Error("expected new access_token cookie")
				}
				if newRefreshCookie == nil {
					t.Error("expected new refresh_token cookie")
				}
			}
		})
	}
}

func TestRefreshTokenRotation(t *testing.T) {
	t.Parallel()

	// Create setup with very short access token TTL
	setup := newShortTTLTestSetup(t, 1*time.Millisecond)
	defer setup.Close()

	client := &http.Client{}

	// Login to get initial tokens
	loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	cookies := getCookies(loginResp)
	loginResp.Body.Close()

	originalRefresh := findCookie(cookies, "refresh_token")
	if originalRefresh == nil {
		t.Fatal("expected refresh_token cookie")
	}

	// Wait for access token to expire
	time.Sleep(10 * time.Millisecond)

	// Use refresh token to get new tokens
	req1, _ := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
	req1.AddCookie(originalRefresh)

	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("failed to do first request: %v", err)
	}

	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected first refresh to succeed, got %d", resp1.StatusCode)
	}

	newCookies := getCookies(resp1)
	resp1.Body.Close()

	newRefresh := findCookie(newCookies, "refresh_token")
	if newRefresh == nil {
		t.Fatal("expected new refresh_token cookie")
	}

	// Verify tokens rotated (new token is different)
	if newRefresh.Value == originalRefresh.Value {
		t.Error("refresh token should have rotated to a new value")
	}

	// Wait for new access token to expire
	time.Sleep(10 * time.Millisecond)

	// Try to use the OLD refresh token again - should fail
	req2, _ := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
	req2.AddCookie(originalRefresh) // Use old token

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("failed to do second request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected old refresh token to be invalid (401), got %d", resp2.StatusCode)
	}
}

func TestRefreshTokenRotationNewTokenWorks(t *testing.T) {
	t.Parallel()

	// Create setup with very short access token TTL
	setup := newShortTTLTestSetup(t, 1*time.Millisecond)
	defer setup.Close()

	client := &http.Client{}

	// Login to get initial tokens
	loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	cookies := getCookies(loginResp)
	loginResp.Body.Close()

	originalRefresh := findCookie(cookies, "refresh_token")
	if originalRefresh == nil {
		t.Fatal("expected refresh_token cookie")
	}

	// Wait for access token to expire
	time.Sleep(10 * time.Millisecond)

	// Use refresh token to get new tokens
	req1, _ := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
	req1.AddCookie(originalRefresh)

	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("failed to do first request: %v", err)
	}

	newCookies := getCookies(resp1)
	resp1.Body.Close()

	newRefresh := findCookie(newCookies, "refresh_token")
	if newRefresh == nil {
		t.Fatal("expected new refresh_token cookie")
	}

	// Wait for new access token to expire
	time.Sleep(10 * time.Millisecond)

	// Use NEW refresh token - should work
	req2, _ := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
	req2.AddCookie(newRefresh) // Use new token

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("failed to do second request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected new refresh token to work (200), got %d", resp2.StatusCode)
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

// Ensure unused import doesn't fail
var _ = os.Remove
