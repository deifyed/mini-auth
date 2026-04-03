package tests

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func updatePasswordRequest(oldPassword, newPassword string) string {
	return fmt.Sprintf(`{"old_password":"%s","new_password":"%s"}`, oldPassword, newPassword)
}

func doUpdatePassword(t *testing.T, serverURL string, cookies []*http.Cookie, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, serverURL+"/update-password", strings.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	for _, c := range cookies {
		req.AddCookie(c)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}

	return resp
}

func TestUpdatePassword(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		oldPassword    string
		newPassword    string
		expectedStatus int
	}{
		"valid old password updates successfully": {
			oldPassword:    testPassword,
			newPassword:    "newpassword456",
			expectedStatus: http.StatusNoContent,
		},
		"wrong old password returns 401": {
			oldPassword:    "wrongpassword",
			newPassword:    "newpassword456",
			expectedStatus: http.StatusUnauthorized,
		},
		"empty old password returns 400": {
			oldPassword:    "",
			newPassword:    "newpassword456",
			expectedStatus: http.StatusBadRequest,
		},
		"empty new password returns 400": {
			oldPassword:    testPassword,
			newPassword:    "",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			setup := newTestSetup(t)
			defer setup.Close()

			// Login first to get auth cookies
			loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
			defer loginResp.Body.Close()

			if loginResp.StatusCode != http.StatusOK {
				t.Fatalf("login failed: got status %d", loginResp.StatusCode)
			}

			cookies := getCookies(loginResp)

			resp := doUpdatePassword(t, setup.Server.URL, cookies, updatePasswordRequest(tc.oldPassword, tc.newPassword))
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}
		})
	}
}

func TestUpdatePasswordUnauthenticated(t *testing.T) {
	t.Parallel()

	setup := newTestSetup(t)
	defer setup.Close()

	// No cookies — should be rejected
	resp := doUpdatePassword(t, setup.Server.URL, nil, updatePasswordRequest(testPassword, "newpassword456"))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestUpdatePasswordInvalidJSON(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body           string
		expectedStatus int
	}{
		"malformed JSON returns 400": {
			body:           `{"old_password": "test"`,
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

			loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
			defer loginResp.Body.Close()

			cookies := getCookies(loginResp)

			resp := doUpdatePassword(t, setup.Server.URL, cookies, tc.body)
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}
		})
	}
}

func TestUpdatePasswordNewPasswordWorks(t *testing.T) {
	t.Parallel()

	setup := newTestSetup(t)
	defer setup.Close()

	const newPassword = "updatedpassword789"

	// Login with original credentials
	loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	defer loginResp.Body.Close()

	cookies := getCookies(loginResp)

	// Change password
	resp := doUpdatePassword(t, setup.Server.URL, cookies, updatePasswordRequest(testPassword, newPassword))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	// Login with new password should succeed
	newLoginResp := doLogin(t, setup.Server.URL, testUsername, newPassword)
	defer newLoginResp.Body.Close()

	if newLoginResp.StatusCode != http.StatusOK {
		t.Errorf("login with new password: expected status %d, got %d", http.StatusOK, newLoginResp.StatusCode)
	}

	// Login with old password should fail
	oldLoginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	defer oldLoginResp.Body.Close()

	if oldLoginResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("login with old password: expected status %d, got %d", http.StatusUnauthorized, oldLoginResp.StatusCode)
	}
}

func TestUpdatePasswordInvalidatesRefreshTokens(t *testing.T) {
	t.Parallel()

	setup := newTestSetup(t)
	defer setup.Close()

	// Login to get cookies
	loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	defer loginResp.Body.Close()

	cookies := getCookies(loginResp)
	refreshCookie := findCookie(cookies, "refresh_token")
	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie from login")
	}

	// Change password
	resp := doUpdatePassword(t, setup.Server.URL, cookies, updatePasswordRequest(testPassword, "newpassword456"))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	// Attempt to access a protected route using the old refresh token should fail
	req, err := http.NewRequest(http.MethodGet, setup.Server.URL+"/protected", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.AddCookie(refreshCookie)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	protectedResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}
	defer protectedResp.Body.Close()

	if protectedResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old refresh token should be invalid: expected status %d, got %d", http.StatusUnauthorized, protectedResp.StatusCode)
	}
}

func TestUpdatePasswordClearsCookies(t *testing.T) {
	t.Parallel()

	setup := newTestSetup(t)
	defer setup.Close()

	loginResp := doLogin(t, setup.Server.URL, testUsername, testPassword)
	defer loginResp.Body.Close()

	cookies := getCookies(loginResp)

	resp := doUpdatePassword(t, setup.Server.URL, cookies, updatePasswordRequest(testPassword, "newpassword456"))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	// Response should include Set-Cookie headers that clear both tokens
	responseCookies := getCookies(resp)

	accessCookie := findCookie(responseCookies, "access_token")
	if accessCookie == nil {
		t.Fatal("expected access_token Set-Cookie header to clear cookie")
	}
	if accessCookie.MaxAge != -1 {
		t.Errorf("access_token cookie MaxAge: expected -1, got %d", accessCookie.MaxAge)
	}

	refreshCookie := findCookie(responseCookies, "refresh_token")
	if refreshCookie == nil {
		t.Fatal("expected refresh_token Set-Cookie header to clear cookie")
	}
	if refreshCookie.MaxAge != -1 {
		t.Errorf("refresh_token cookie MaxAge: expected -1, got %d", refreshCookie.MaxAge)
	}
}
