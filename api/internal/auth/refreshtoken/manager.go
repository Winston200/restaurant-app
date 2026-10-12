package refreshtoken

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	ErrMissingSecret = errors.New("refresh token secret is required")
)

type Manager struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

func NewManager(secret string, ttl time.Duration) (*Manager, error) {
	if secret == "" {
		return nil, ErrMissingSecret
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("refresh token ttl must be positive")
	}
	return &Manager{
		secret: []byte(secret),
		ttl:    ttl,
		now:    time.Now,
	}, nil
}

func (m *Manager) TTL() time.Duration {
	return m.ttl
}

func (m *Manager) SetNowFunc(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

func (m *Manager) Issue() (rawToken string, tokenHash string, expiresAt time.Time, expiresIn int64, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", time.Time{}, 0, fmt.Errorf("generate refresh token: %w", err)
	}

	rawToken = base64.RawURLEncoding.EncodeToString(raw)
	now := m.now().UTC()
	expiresAt = now.Add(m.ttl)
	tokenHash = m.Hash(rawToken)
	expiresIn = int64(m.ttl.Seconds())
	return rawToken, tokenHash, expiresAt, expiresIn, nil
}

func (m *Manager) Hash(rawToken string) string {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(rawToken))
	return hex.EncodeToString(mac.Sum(nil))
}
