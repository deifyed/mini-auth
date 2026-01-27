package simpleauth

import "errors"

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// User represents an authenticated user.
type User struct {
	ID       int64
	Username string
}

// Datastore defines the interface for user authentication storage.
type Datastore interface {
	// Authenticate validates username and password, returning the user if valid.
	Authenticate(username, password string) (User, error)

	// GetUserByID retrieves a user by their ID.
	GetUserByID(id int64) (User, error)
}
