package simpleauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

const refreshTokenBytes = 32

// accessClaims contains the JWT payload for access tokens.
type accessClaims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// generateAccessToken creates a JWT access token for the given user.
func generateAccessToken(user User, ttl time.Duration, secret []byte) (string, error) {
	now := time.Now()
	claims := accessClaims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// validateAccessToken parses and validates a JWT access token, returning the claims if valid.
func validateAccessToken(tokenString string, secret []byte) (*accessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &accessClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*accessClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// generateRefreshToken creates a cryptographically secure random refresh token.
func generateRefreshToken() (string, error) {
	b := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
