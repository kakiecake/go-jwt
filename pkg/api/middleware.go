package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"github.com/kakiecake/go-jwt/pkg/auth"
)

type Middleware func(next http.HandlerFunc) http.HandlerFunc

func combine(middlewares ...Middleware) Middleware {
	if len(middlewares) == 0 {
		panic("combine was provided 0 middlewares")
	}

	if len(middlewares) == 1 {
		return middlewares[0]
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		slices.Reverse(middlewares)
		firstMw := middlewares[0]
		lastHandler := firstMw(next)
		for _, mw := range middlewares[1:] {
			lastHandler = mw(lastHandler)
		}
		return lastHandler
	}
}

func refreshTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(refreshTokenCookieName)
		if err != nil {
			respondWithUnauthorized(w)
			return
		}
		refreshToken := cookie.Value
		ctx := context.WithValue(r.Context(), refreshTokenContextName, refreshToken)
		next(w, r.WithContext(ctx))
	} 
}

/*
combine(basicMiddleware, newAuthMiddleware(authService))

basicMiddleware(
	newAuthMiddleware(authService)
)
*/

func errorHandlingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("Error encountered!\n%v", err)
				respondWithServerError(w)
				return
			}
		}()

		next.ServeHTTP(w, r)
	}
}

func newAuthMiddleware(authService auth.AuthService) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		re := regexp.MustCompile(`^Bearer\s(\S+)$`)

		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			matches := re.FindStringSubmatch(authHeader)
			if len(matches) != 2 {
				respondWithUnauthorized(w)
				return
			}
			accessToken := matches[1]
			userID, err := authService.GetUserIDFromToken(accessToken)
			if errors.Is(err, auth.ErrExpired) {
				respondWithForbidden(w)
				return
			}
			if err != nil {
				respondWithServerError(w)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), userIDContextName, userID))
			next(w, r)
		}
	}
}
