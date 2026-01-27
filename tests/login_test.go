package tests

import (
	"net/http"
	"strings"
	"testing"
)

func TestLogin(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		username       string
		password       string
		expectedStatus int
		expectCookies  bool
	}{
		"valid credentials returns 200 and sets cookies": {
			username:       testUsername,
			password:       testPassword,
			expectedStatus: http.StatusOK,
			expectCookies:  true,
		},
		"invalid password returns 401": {
			username:       testUsername,
			password:       "wrongpassword",
			expectedStatus: http.StatusUnauthorized,
			expectCookies:  false,
		},
		"non-existent user returns 401": {
			username:       "nonexistent",
			password:       testPassword,
			expectedStatus: http.StatusUnauthorized,
			expectCookies:  false,
		},
		"empty username returns 400": {
			username:       "",
			password:       testPassword,
			expectedStatus: http.StatusBadRequest,
			expectCookies:  false,
		},
		"empty password returns 400": {
			username:       testUsername,
			password:       "",
			expectedStatus: http.StatusBadRequest,
			expectCookies:  false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			setup := newTestSetup(t)
			defer setup.Close()

			resp := doLogin(t, setup.Server.URL, tc.username, tc.password)
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}

			cookies := getCookies(resp)
			accessCookie := findCookie(cookies, "access_token")
			refreshCookie := findCookie(cookies, "refresh_token")

			if tc.expectCookies {
				if accessCookie == nil {
					t.Error("expected access_token cookie, got none")
				}
				if refreshCookie == nil {
					t.Error("expected refresh_token cookie, got none")
				}
				if accessCookie != nil && !accessCookie.HttpOnly {
					t.Error("access_token cookie should be HttpOnly")
				}
				if refreshCookie != nil && !refreshCookie.HttpOnly {
					t.Error("refresh_token cookie should be HttpOnly")
				}
			} else {
				if accessCookie != nil {
					t.Error("expected no access_token cookie")
				}
				if refreshCookie != nil {
					t.Error("expected no refresh_token cookie")
				}
			}
		})
	}
}

func TestLoginMethodNotAllowed(t *testing.T) {
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

			req, err := http.NewRequest(tc.method, setup.Server.URL+"/login", strings.NewReader(loginRequest(testUsername, testPassword)))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

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

func TestLoginInvalidJSON(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body           string
		expectedStatus int
	}{
		"malformed JSON returns 400": {
			body:           `{"username": "test"`,
			expectedStatus: http.StatusBadRequest,
		},
		"empty body returns 400": {
			body:           ``,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			setup := newTestSetup(t)
			defer setup.Close()

			req, err := http.NewRequest(http.MethodPost, setup.Server.URL+"/login", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

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
