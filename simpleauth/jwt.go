package simpleauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

type tokenType string

const (
	accessToken  tokenType = "access"
	refreshToken tokenType = "refresh"
)

// jwtHeader is the standard JWT header for HS256.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// jwtClaims contains the JWT payload.
type jwtClaims struct {
	UserID    int64     `json:"sub"`
	Username  string    `json:"username"`
	TokenType tokenType `json:"type"`
	IssuedAt  int64     `json:"iat"`
	ExpiresAt int64     `json:"exp"`
}

func (c *jwtClaims) isExpired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// generateToken creates a JWT for the given user.
func generateToken(user User, tokenType tokenType, ttl time.Duration, secret []byte) (string, error) {
	header := jwtHeader{Alg: "HS256", Typ: "JWT"}
	claims := jwtClaims{
		UserID:    user.ID,
		Username:  user.Username,
		TokenType: tokenType,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(ttl).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := signHS256([]byte(signingInput), secret)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

// validateToken parses and validates a JWT, returning the claims if valid.
func validateToken(tokenString string, expectedType tokenType, secret []byte) (*jwtClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerB64, claimsB64, signatureB64 := parts[0], parts[1], parts[2]

	// Verify signature
	signingInput := headerB64 + "." + claimsB64
	expectedSig := signHS256([]byte(signingInput), secret)
	actualSig, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return nil, ErrInvalidToken
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	// Validate token type
	if claims.TokenType != expectedType {
		return nil, ErrInvalidToken
	}

	// Check expiration
	if claims.isExpired() {
		return nil, ErrExpiredToken
	}

	return &claims, nil
}

func signHS256(data, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return h.Sum(nil)
}
