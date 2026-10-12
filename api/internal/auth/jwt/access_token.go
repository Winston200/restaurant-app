package authjwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingSecret   = errors.New("jwt access secret is required")
	ErrSignToken       = errors.New("failed to sign access token")
	ErrInvalidToken    = errors.New("invalid access token")
	ErrTokenExpired    = errors.New("access token expired")
	ErrInvalidIssuer   = errors.New("invalid token issuer")
	ErrInvalidAdminID  = errors.New("invalid admin id in token")
)

// AccessClaims holds Access Token payload fields required by the product.
type AccessClaims struct {
	AdminID   int64  `json:"admin_id"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	Issuer    string `json:"issuer"`
}

func (c AccessClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

func (c AccessClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c AccessClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

func (c AccessClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c AccessClaims) GetSubject() (string, error) {
	return "", nil
}

func (c AccessClaims) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

type AccessTokenManager struct {
	secret []byte
	ttl    time.Duration
	issuer string
	now    func() time.Time
}

func NewAccessTokenManager(secret string, ttl time.Duration, issuer string) (*AccessTokenManager, error) {
	if secret == "" {
		return nil, ErrMissingSecret
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("access token ttl must be positive")
	}
	if issuer == "" {
		issuer = "restaurant-api"
	}
	return &AccessTokenManager{
		secret: []byte(secret),
		ttl:    ttl,
		issuer: issuer,
		now:    time.Now,
	}, nil
}

// SetNowFunc overrides the clock (tests only).
func (m *AccessTokenManager) SetNowFunc(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

type IssuedAccessToken struct {
	Token     string
	ExpiresIn int64
}

func (m *AccessTokenManager) IssueAccessToken(adminID int64) (IssuedAccessToken, error) {
	if adminID <= 0 {
		return IssuedAccessToken{}, fmt.Errorf("invalid admin id")
	}

	now := m.now().UTC()
	exp := now.Add(m.ttl)
	claims := AccessClaims{
		AdminID:   adminID,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		Issuer:    m.issuer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return IssuedAccessToken{}, fmt.Errorf("%w: %v", ErrSignToken, err)
	}

	return IssuedAccessToken{
		Token:     signed,
		ExpiresIn: int64(m.ttl.Seconds()),
	}, nil
}

// ParseAccessToken verifies signature, expiry, and issuer before returning claims.
func (m *AccessTokenManager) ParseAccessToken(tokenString string) (*AccessClaims, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}

	parsed, err := jwt.ParseWithClaims(
		tokenString,
		&AccessClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("%w: unexpected signing method", ErrInvalidToken)
			}
			return m.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(m.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			return nil, ErrInvalidIssuer
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := parsed.Claims.(*AccessClaims)
	if !ok || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	if claims.AdminID <= 0 {
		return nil, ErrInvalidAdminID
	}
	if claims.Issuer != m.issuer {
		return nil, ErrInvalidIssuer
	}
	return claims, nil
}
