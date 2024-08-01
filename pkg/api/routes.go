package api

import (
	"errors"
	"net/http"

	"github.com/kakiecake/go-jwt/pkg/auth"
)

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /user/register", s.handleRegister())
	mux.HandleFunc("POST /user/login", s.handleLogin())
	mux.HandleFunc("POST /token/refresh", refreshTokenMiddleware(s.handleRefreshToken()))
	mux.HandleFunc("POST /token/revoke", refreshTokenMiddleware(s.handleRevokeToken()))

	mux.HandleFunc("GET /public", s.handlePublic())
	mux.HandleFunc("GET /me", combine(
		errorHandlingMiddleware,
		newAuthMiddleware(*s.authService),
	)(s.handleMe()))

	return mux
}

func (s *Server) handleLogin() http.HandlerFunc {
	type request struct {
		Login    string `json:"login" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		err := decodeWithValidation(r, &body, s.validate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		access, refresh, err := s.userService.Login(body.Login, body.Password)
		if errors.Is(err, auth.ErrNoUser) {
			http.Error(w, "Invalid login/password combination", http.StatusForbidden)
			return
		}
		if err != nil {
			respondWithServerError(w)
			return
		}

		refreshTokenCookie := http.Cookie{
			Name:     "refreshToken",
			Value:    refresh,
			Path:     "/token",
			HttpOnly: true,
			MaxAge:   s.authService.RefreshTokenExpirySec(),
		}
		http.SetCookie(w, &refreshTokenCookie)

		respondWithJson(w, map[string]interface{}{"accessToken": access})
	}
}

func (s *Server) handleRegister() http.HandlerFunc {
	type request struct {
		Login    string `json:"login" validate:"required,min=6,max=16"`
		Password string `json:"password" validate:"required,min=8,max=32"`
		FullName string `json:"fullName" validate:"required,min=6,max=32"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var body request
		err := decodeWithValidation(r, &body, s.validate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		err = s.userService.Register(body.FullName, body.Login, body.Password)
		if errors.Is(err, auth.ErrUserExists) {
			respondWithError(w, err, http.StatusForbidden)
			return
		}
		if err != nil {
			respondWithServerError(w)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) handleRefreshToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Context().Value("refreshToken").(string)
		access, refresh, err := s.authService.UpdateTokenPair(tokenStr)
		if errors.Is(err, auth.ErrInvalidToken) {
			respondWithForbidden(w)
			return
		}
		if err != nil {
			respondWithServerError(w)
			return
		}

		refreshTokenCookie := http.Cookie{
			Name:     refreshTokenCookieName,
			Value:    refresh,
			Path:     "/token",
			HttpOnly: true,
			MaxAge:   s.authService.RefreshTokenExpirySec(),
		}
		http.SetCookie(w, &refreshTokenCookie)
		respondWithJson(w, map[string]string{"accessToken": access})
	}
}

func (s *Server) handleRevokeToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refreshToken := r.Context().Value(refreshTokenContextName).(string)
		if err := s.authService.RevokeRefreshToken(refreshToken); err != nil {
			respondWithServerError(w)
			return
		}
		respondWithNoContent(w)
	}
}

func (s *Server) handlePublic() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("This is a public endpoint. Hello there!"))
	}
}

func (s *Server) handleMe() http.HandlerFunc {
	type response struct {
		Login    string `json:"login"`
		FullName string `json:"fullName"`
		ID       int    `json:"id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value(userIDContextName).(auth.UserID)
		user, err := s.userService.GetUserByID(userID)
		if err != nil {
			respondWithServerError(w)
			return
		}
		response := response{Login: user.Login, FullName: user.FullName, ID: int(user.ID)}
		respondWithJson(w, &response)
	}
}
