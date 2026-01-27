package tests

import (
	"net/http"
	"testing"
)

func TestLogout(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		loginFirst     bool
		expectedStatus int
	}{
		"logout after login clears cookies": {
			loginFirst:     true,
			expectedStatus: http.StatusOK,
		},
		"logout without login still returns 200": {
			loginFirst:     false,
			expectedStatus: http.StatusOK,
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
			if tc.loginFirst {
				loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
				cookies = getCookies(loginResp)
				loginResp.Body.Close()
			}

			req, err := http.NewRequest(http.MethodPost, setup.Server.URL+"/logout", nil)
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

			// Check that cookies are cleared (MaxAge < 0 or empty value)
			logoutCookies := getCookies(resp)
			accessCookie := findCookie(logoutCookies, "access_token")
			refreshCookie := findCookie(logoutCookies, "refresh_token")

			if accessCookie != nil && accessCookie.MaxAge > 0 {
				t.Error("access_token cookie should be cleared")
			}
			if refreshCookie != nil && refreshCookie.MaxAge > 0 {
				t.Error("refresh_token cookie should be cleared")
			}
		})
	}
}

func TestLogoutInvalidatesRefreshToken(t *testing.T) {
	t.Parallel()

	setup := newTestSetup(t)
	defer setup.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Login first
	loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	cookies := getCookies(loginResp)
	loginResp.Body.Close()

	refreshCookie := findCookie(cookies, "refresh_token")
	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie after login")
	}

	// Logout
	logoutReq, _ := http.NewRequest(http.MethodPost, setup.Server.URL+"/logout", nil)
	for _, c := range cookies {
		logoutReq.AddCookie(c)
	}
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("failed to logout: %v", err)
	}
	logoutResp.Body.Close()

	// Try to access protected route with old refresh token
	protectedReq, _ := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
	protectedReq.AddCookie(refreshCookie) // Use old refresh token

	protectedResp, err := client.Do(protectedReq)
	if err != nil {
		t.Fatalf("failed to access protected route: %v", err)
	}
	defer protectedResp.Body.Close()

	if protectedResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalidated refresh token, got %d", protectedResp.StatusCode)
	}
}

func TestLogoutMethodNotAllowed(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		method         string
		expectedStatus int
	}{
		"GET returns 405": {
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		"PUT returns 405": {
			method:         http.MethodPut,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		"DELETE returns 405": {
			method:         http.MethodDelete,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			setup := newTestSetup(t)
			defer setup.Close()

			req, err := http.NewRequest(tc.method, setup.Server.URL+"/logout", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			client := &http.Client{}
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
