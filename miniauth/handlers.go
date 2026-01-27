package miniauth

import (
	"encoding/json"
	"net/http"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login returns a handler that accepts POST requests with username/password.
// On success, sets access_token and refresh_token cookies.
func Login(m *Middleware) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Username == "" || req.Password == "" {
			http.Error(w, "Username and password required", http.StatusBadRequest)
			return
		}

		user, err := m.Datastore.Authenticate(req.Username, req.Password)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		if err := m.setTokenCookies(w, user); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// Logout returns a handler that clears the authentication cookies and invalidates the refresh token.
func Logout(m *Middleware) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Delete refresh token from DB if present
		if cookie, err := r.Cookie(refreshTokenCookie); err == nil {
			m.Datastore.DeleteRefreshToken(cookie.Value)
		}

		m.clearTokenCookies(w)
		w.WriteHeader(http.StatusOK)
	}
}
