package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"restaurant-api/internal/handler"
	"restaurant-api/internal/service"
)

type stubAuthService struct {
	result *service.LoginResult
	pair   *service.TokenPair
	me     *service.AdminMe
	err    error
}

func (s stubAuthService) Login(ctx context.Context, in service.LoginInput) (*service.LoginResult, error) {
	return s.result, s.err
}

func (s stubAuthService) Refresh(ctx context.Context, in service.RefreshInput) (*service.TokenPair, error) {
	return s.pair, s.err
}

func (s stubAuthService) Logout(ctx context.Context, in service.LogoutInput) error {
	return s.err
}

func (s stubAuthService) GetMe(ctx context.Context, adminID int64) (*service.AdminMe, error) {
	return s.me, s.err
}

func TestAdminHandler_Login(t *testing.T) {
	phone := "13800000000"
	h := handler.NewAdminHandler(stubAuthService{
		result: &service.LoginResult{
			AccessToken:      "aaa.bbb.ccc",
			RefreshToken:     "refresh-token",
			TokenType:        "Bearer",
			ExpiresIn:        900,
			RefreshExpiresIn: 604800,
			Admin: service.LoginAdmin{
				ID:    "1",
				Phone: &phone,
			},
		},
	})

	body := []byte(`{"username":"admin","password":"123456"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	data := resp["data"].(map[string]interface{})
	if data["refresh_token"] != "refresh-token" {
		t.Fatalf("missing refresh_token: %#v", data)
	}
}

func TestAdminHandler_RefreshAndLogout(t *testing.T) {
	h := handler.NewAdminHandler(stubAuthService{
		pair: &service.TokenPair{
			AccessToken:      "new.access",
			RefreshToken:     "new.refresh",
			TokenType:        "Bearer",
			ExpiresIn:        900,
			RefreshExpiresIn: 604800,
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/refresh", bytes.NewReader([]byte(`{"refresh_token":"old"}`)))
	rec := httptest.NewRecorder()
	h.Refresh(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/logout", bytes.NewReader([]byte(`{"refresh_token":"old"}`)))
	rec = httptest.NewRecorder()
	h.Logout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d", rec.Code)
	}
}

func TestAdminHandler_LoginInvalidCredentials(t *testing.T) {
	h := handler.NewAdminHandler(stubAuthService{err: service.ErrInvalidCredentials})
	body := []byte(`{"username":"admin","password":"bad"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
