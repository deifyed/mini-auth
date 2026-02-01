package miniauth

import (
	"errors"
	"time"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenNotFound      = errors.New("refresh token not found")
)

// User represents an authenticated user.
type User struct {
	ID       int64
	Username string
}

// Datastore defines the interface for user authentication storage.
type Datastore interface {
	// CreateUser creates a new user with the given username and password.
	CreateUser(username, password string) (User, error)

	// Authenticate validates username and password, returning the user if valid.
	Authenticate(username, password string) (User, error)

	// GetUserByID retrieves a user by their ID.
	GetUserByID(id int64) (User, error)

	// StoreRefreshToken stores a refresh token for a user.
	StoreRefreshToken(token string, userID int64, expiresAt time.Time) error

	// ValidateRefreshToken checks if a refresh token is valid and returns the user ID.
	ValidateRefreshToken(token string) (userID int64, err error)

	// DeleteRefreshToken removes a specific refresh token.
	DeleteRefreshToken(token string) error

	// DeleteUserRefreshTokens removes all refresh tokens for a user (logout everywhere).
	DeleteUserRefreshTokens(userID int64) error
}
