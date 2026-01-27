package simpleauth

import (
	"database/sql"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Sqlite3 implements the Datastore interface using SQLite3.
type Sqlite3 struct {
	Path string
	db   *sql.DB
}

// Init initializes the database connection and creates tables if needed.
func (s *Sqlite3) Init() error {
	db, err := sql.Open("sqlite", s.Path)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}

	s.db = db

	if err := s.createTables(); err != nil {
		return fmt.Errorf("creating tables: %w", err)
	}

	return nil
}

func (s *Sqlite3) createTables() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	return err
}

// Close closes the database connection.
func (s *Sqlite3) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Authenticate validates username and password.
func (s *Sqlite3) Authenticate(username, password string) (User, error) {
	var user User
	var passwordHash string

	err := s.db.QueryRow(
		"SELECT id, username, password_hash FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash)

	if err == sql.ErrNoRows {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("querying user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return User{}, ErrInvalidCredentials
	}

	return user, nil
}

// GetUserByID retrieves a user by ID.
func (s *Sqlite3) GetUserByID(id int64) (User, error) {
	var user User

	err := s.db.QueryRow(
		"SELECT id, username FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username)

	if err == sql.ErrNoRows {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("querying user: %w", err)
	}

	return user, nil
}

// CreateUser creates a new user with a hashed password.
func (s *Sqlite3) CreateUser(username, password string) (User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, fmt.Errorf("hashing password: %w", err)
	}

	result, err := s.db.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username, string(hash),
	)
	if err != nil {
		return User{}, fmt.Errorf("inserting user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("getting last insert id: %w", err)
	}

	return User{ID: id, Username: username}, nil
}

// StoreRefreshToken stores a refresh token for a user.
func (s *Sqlite3) StoreRefreshToken(token string, userID int64, expiresAt time.Time) error {
	_, err := s.db.Exec(
		"INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
		token, userID, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("storing refresh token: %w", err)
	}
	return nil
}

// ValidateRefreshToken checks if a refresh token is valid and returns the user ID.
func (s *Sqlite3) ValidateRefreshToken(token string) (int64, error) {
	var userID int64
	var expiresAt time.Time

	err := s.db.QueryRow(
		"SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?",
		token,
	).Scan(&userID, &expiresAt)

	if err == sql.ErrNoRows {
		return 0, ErrTokenNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("querying refresh token: %w", err)
	}

	if time.Now().After(expiresAt) {
		s.DeleteRefreshToken(token)
		return 0, ErrTokenNotFound
	}

	return userID, nil
}

// DeleteRefreshToken removes a specific refresh token.
func (s *Sqlite3) DeleteRefreshToken(token string) error {
	_, err := s.db.Exec("DELETE FROM refresh_tokens WHERE token = ?", token)
	if err != nil {
		return fmt.Errorf("deleting refresh token: %w", err)
	}
	return nil
}

// DeleteUserRefreshTokens removes all refresh tokens for a user.
func (s *Sqlite3) DeleteUserRefreshTokens(userID int64) error {
	_, err := s.db.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("deleting user refresh tokens: %w", err)
	}
	return nil
}
