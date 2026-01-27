package tests

import (
	"io"
	"net/http"
	"testing"
)

func TestProtection(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		authenticated   bool
		expectedStatus  int
		expectedBodyContains string
	}{
		"authenticated request returns 200": {
			authenticated:        true,
			expectedStatus:       http.StatusOK,
			expectedBodyContains: "Hello, " + testUsername,
		},
		"unauthenticated request returns 401": {
			authenticated:        false,
			expectedStatus:       http.StatusUnauthorized,
			expectedBodyContains: "Unauthorized",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			setup := newTestSetup(t)
			defer setup.Close()

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			var cookies []*http.Cookie
			if tc.authenticated {
				loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
				cookies = getCookies(loginResp)
				loginResp.Body.Close()
			}

			req, err := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			for _, c := range cookies {
				req.AddCookie(c)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("failed to do request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}

			body, _ := io.ReadAll(resp.Body)
			if tc.expectedBodyContains != "" && string(body) == "" {
				t.Errorf("expected body to contain %q, got empty", tc.expectedBodyContains)
			}
		})
	}
}

func TestProtectionWithInvalidTokens(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		accessToken    string
		refreshToken   string
		expectedStatus int
	}{
		"invalid access token returns 401": {
			accessToken:    "invalid.access.token",
			refreshToken:   "",
			expectedStatus: http.StatusUnauthorized,
		},
		"invalid refresh token returns 401": {
			accessToken:    "",
			refreshToken:   "invalid-refresh-token",
			expectedStatus: http.StatusUnauthorized,
		},
		"both invalid tokens returns 401": {
			accessToken:    "invalid.access.token",
			refreshToken:   "invalid-refresh-token",
			expectedStatus: http.StatusUnauthorized,
		},
		"empty tokens returns 401": {
			accessToken:    "",
			refreshToken:   "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			setup := newTestSetup(t)
			defer setup.Close()

			client := &http.Client{}

			req, err := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			if tc.accessToken != "" {
				req.AddCookie(&http.Cookie{Name: "access_token", Value: tc.accessToken})
			}
			if tc.refreshToken != "" {
				req.AddCookie(&http.Cookie{Name: "refresh_token", Value: tc.refreshToken})
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("failed to do request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}
		})
	}
}

func TestProtectionUserInContext(t *testing.T) {
	t.Parallel()

	setup := newTestSetup(t)
	defer setup.Close()

	client := &http.Client{}

	// Login to get cookies
	loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	cookies := getCookies(loginResp)
	loginResp.Body.Close()

	// Access protected route
	req, _ := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	expectedBody := "Hello, " + testUsername + "!"

	if string(body) != expectedBody {
		t.Errorf("expected body %q, got %q", expectedBody, string(body))
	}
}

func TestProtectionWithOnlyAccessToken(t *testing.T) {
	t.Parallel()

	setup := newTestSetup(t)
	defer setup.Close()

	client := &http.Client{}

	// Login to get cookies
	loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	cookies := getCookies(loginResp)
	loginResp.Body.Close()

	accessCookie := findCookie(cookies, "access_token")
	if accessCookie == nil {
		t.Fatal("expected access_token cookie")
	}

	// Access protected route with only access token
	req, _ := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
	req.AddCookie(accessCookie)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 with valid access token, got %d", resp.StatusCode)
	}
}
