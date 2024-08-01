package api

import (
	"github.com/go-playground/validator/v10"
	"github.com/kakiecake/go-jwt/pkg/auth"
)

type Server struct {
	userService *auth.UserService
	authService *auth.AuthService
	validate    *validator.Validate
}

func NewServer(authService *auth.AuthService, userService *auth.UserService) *Server {
	return &Server{
		userService: userService,
		authService: authService,
		validate:    validator.New(validator.WithRequiredStructEnabled()),
	}
}
