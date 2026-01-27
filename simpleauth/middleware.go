package simpleauth

import (
	"net/http"
	"time"
)

const (
	accessTokenCookie  = "access_token"
	refreshTokenCookie = "refresh_token"

	defaultAccessTTL  = 15 * time.Minute
	defaultRefreshTTL = 7 * 24 * time.Hour
)

// Middleware provides authentication for HTTP handlers.
type Middleware struct {
	Datastore  Datastore
	Secret     []byte
	AccessTTL  time.Duration // Default: 15 minutes
	RefreshTTL time.Duration // Default: 7 days
	Secure     bool          // Set Secure flag on cookies (use true in production)
}

func (m *Middleware) accessTTL() time.Duration {
	if m.AccessTTL == 0 {
		return defaultAccessTTL
	}
	return m.AccessTTL
}

func (m *Middleware) refreshTTL() time.Duration {
	if m.RefreshTTL == 0 {
		return defaultRefreshTTL
	}
	return m.RefreshTTL
}

// Protect wraps a handler to require authentication.
// Unauthenticated requests receive a 401 response.
// If access token is expired but refresh token is valid, new tokens are issued automatically.
func (m *Middleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := m.authenticate(w, r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := setUserInContext(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate attempts to authenticate the request using access token,
// falling back to refresh token if needed.
func (m *Middleware) authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
	// Try access token first
	if cookie, err := r.Cookie(accessTokenCookie); err == nil {
		claims, err := validateToken(cookie.Value, accessToken, m.Secret)
		if err == nil {
			return &User{ID: claims.UserID, Username: claims.Username}, nil
		}
	}

	// Try refresh token
	refreshCookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, err := validateToken(refreshCookie.Value, refreshToken, m.Secret)
	if err != nil {
		return nil, err
	}

	// Refresh token valid - get fresh user data and issue new tokens
	user, err := m.Datastore.GetUserByID(claims.UserID)
	if err != nil {
		return nil, err
	}

	if err := m.setTokenCookies(w, user); err != nil {
		return nil, err
	}

	return user, nil
}

// setTokenCookies generates and sets both access and refresh token cookies.
func (m *Middleware) setTokenCookies(w http.ResponseWriter, user *User) error {
	access, err := generateToken(user, accessToken, m.accessTTL(), m.Secret)
	if err != nil {
		return err
	}

	refresh, err := generateToken(user, refreshToken, m.refreshTTL(), m.Secret)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenCookie,
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(m.accessTTL().Seconds()),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(m.refreshTTL().Seconds()),
	})

	return nil
}

// clearTokenCookies removes both token cookies.
func (m *Middleware) clearTokenCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
