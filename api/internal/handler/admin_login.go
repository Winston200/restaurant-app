package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"restaurant-api/internal/auth"
	"restaurant-api/internal/response"
	"restaurant-api/internal/service"
)

type adminAuthService interface {
	Login(ctx context.Context, in service.LoginInput) (*service.LoginResult, error)
	Refresh(ctx context.Context, in service.RefreshInput) (*service.TokenPair, error)
	Logout(ctx context.Context, in service.LogoutInput) error
	GetMe(ctx context.Context, adminID int64) (*service.AdminMe, error)
}

type AdminHandler struct {
	auth adminAuthService
}

func NewAdminHandler(auth adminAuthService) *AdminHandler {
	return &AdminHandler{auth: auth}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *AdminHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Fail(w, http.StatusMethodNotAllowed, 40500, "method not allowed")
		return
	}

	var req loginRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		response.Fail(w, http.StatusBadRequest, 40000, "invalid request body")
		return
	}

	result, err := h.auth.Login(r.Context(), service.LoginInput{
		Username: req.Username,
		Password: req.Password,
	})
	if err != nil {
		h.writeAuthError(w, err)
		return
	}

	response.OK(w, result)
}

func (h *AdminHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Fail(w, http.StatusMethodNotAllowed, 40500, "method not allowed")
		return
	}

	var req refreshRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		response.Fail(w, http.StatusBadRequest, 40000, "invalid request body")
		return
	}

	result, err := h.auth.Refresh(r.Context(), service.RefreshInput{RefreshToken: req.RefreshToken})
	if err != nil {
		h.writeAuthError(w, err)
		return
	}

	response.OK(w, result)
}

func (h *AdminHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.Fail(w, http.StatusMethodNotAllowed, 40500, "method not allowed")
		return
	}

	var req logoutRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		response.Fail(w, http.StatusBadRequest, 40000, "invalid request body")
		return
	}

	if err := h.auth.Logout(r.Context(), service.LogoutInput{RefreshToken: req.RefreshToken}); err != nil {
		h.writeAuthError(w, err)
		return
	}

	response.OK(w, map[string]bool{"logged_out": true})
}

func (h *AdminHandler) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		response.Fail(w, http.StatusMethodNotAllowed, 40500, "method not allowed")
		return
	}

	adminID, ok := auth.AdminIDFromContext(r.Context())
	if !ok {
		response.Fail(w, http.StatusUnauthorized, 40102, "unauthorized")
		return
	}

	profile, err := h.auth.GetMe(r.Context(), adminID)
	if err != nil {
		h.writeAuthError(w, err)
		return
	}

	response.OK(w, profile)
}

func (h *AdminHandler) writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrValidation):
		response.Fail(w, http.StatusBadRequest, 40001, "invalid request")
	case errors.Is(err, service.ErrInvalidCredentials):
		response.Fail(w, http.StatusUnauthorized, 40101, "用户名或密码错误")
	case errors.Is(err, service.ErrAdminDisabled):
		response.Fail(w, http.StatusForbidden, 40301, "账号不可用")
	case errors.Is(err, service.ErrTokenIssue):
		response.Fail(w, http.StatusInternalServerError, 50001, "failed to create token")
	case errors.Is(err, service.ErrInvalidRefreshToken),
		errors.Is(err, service.ErrRefreshTokenExpired),
		errors.Is(err, service.ErrRefreshTokenRevoked),
		errors.Is(err, service.ErrRefreshTokenReused):
		response.Fail(w, http.StatusUnauthorized, 40105, "invalid refresh token")
	default:
		response.Fail(w, http.StatusInternalServerError, 50000, "internal server error")
	}
}
