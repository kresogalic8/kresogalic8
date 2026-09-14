package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// Session represents an authenticated user session.
type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
}

// ErrExpired is returned when a session has expired.
var ErrExpired = errors.New("session expired")

// NewSession creates a new session for the given user identifier.
func NewSession(userID string, ttl time.Duration) (*Session, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return &Session{ID: hex.EncodeToString(buf), UserID: userID, ExpiresAt: time.Now().Add(ttl)}, nil
}

// Validate checks whether the session is still valid.
func (s *Session) Validate(now time.Time) error {
	if now.After(s.ExpiresAt) {
		return ErrExpired
	}
	return nil
}
