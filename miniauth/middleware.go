package miniauth

import (
	"net/http"
	"time"
)

const (
	accessTokenCookie  = "access_token"
	refreshTokenCookie = "refresh_token"

	defaultAccessTTL  = 3 * time.Minute
	defaultRefreshTTL = 7 * 24 * time.Hour
)

// Middleware provides authentication for HTTP handlers.
type Middleware struct {
	Datastore  Datastore
	Secret     []byte
	AccessTTL  time.Duration // Default: 3 minutes
	RefreshTTL time.Duration // Default: 7 days
	Insecure   bool          // Disable Secure flag on cookies (default: false = secure)
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

func (m *Middleware) secureCookie() bool {
	return !m.Insecure
}

// Wrap wraps a handler to require authentication.
// Unauthenticated requests receive a 401 response.
// If access token is expired but refresh token is valid, new tokens are issued automatically.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
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

// authenticate attempts to authenticate the request using access token (stateless),
// falling back to refresh token (DB lookup) if needed.
func (m *Middleware) authenticate(w http.ResponseWriter, r *http.Request) (User, error) {
	// Try access token first (stateless JWT validation)
	if cookie, err := r.Cookie(accessTokenCookie); err == nil {
		claims, err := validateAccessToken(cookie.Value, m.Secret)
		if err == nil {
			return User{ID: claims.UserID, Username: claims.Username}, nil
		}
	}

	// Try refresh token (DB lookup)
	refreshCookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		return User{}, ErrInvalidToken
	}

	// Validate refresh token against DB
	userID, err := m.Datastore.ValidateRefreshToken(refreshCookie.Value)
	if err != nil {
		return User{}, err
	}

	// Get user data
	user, err := m.Datastore.GetUserByID(userID)
	if err != nil {
		return User{}, err
	}

	// Issue a new access token (no refresh token rotation to avoid race conditions
	// with concurrent requests)
	if err := m.setAccessTokenCookie(w, user); err != nil {
		return User{}, err
	}

	return user, nil
}

// setAccessTokenCookie generates and sets only the access token cookie.
// Used during transparent refresh to avoid refresh token rotation.
func (m *Middleware) setAccessTokenCookie(w http.ResponseWriter, user User) error {
	access, err := generateAccessToken(user, m.accessTTL(), m.Secret)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenCookie,
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(m.accessTTL().Seconds()),
	})

	return nil
}

// setTokenCookies generates and sets both access and refresh token cookies.
// The refresh token is stored in the database.
func (m *Middleware) setTokenCookies(w http.ResponseWriter, user User) error {
	access, err := generateAccessToken(user, m.accessTTL(), m.Secret)
	if err != nil {
		return err
	}

	refresh, err := generateRefreshToken()
	if err != nil {
		return err
	}

	// Store refresh token in DB
	expiresAt := time.Now().Add(m.refreshTTL())
	if err := m.Datastore.StoreRefreshToken(refresh, user.ID, expiresAt); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenCookie,
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(m.accessTTL().Seconds()),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie(),
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
		Secure:   m.secureCookie(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
