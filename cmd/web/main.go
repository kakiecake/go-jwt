package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kakiecake/go-jwt/pkg/api"
	"github.com/kakiecake/go-jwt/pkg/auth"
)

const JWT_SECRET_KEY = "TESTONLY"
const REFRESH_TOKEN_EXPIRY = time.Duration(time.Minute * 2)
const ACCESS_TOKEN_EXPIRY = time.Duration(time.Second * 30)
const DB_URI = "postgresql://user:12345678@localhost:5434/auth?sslmode=disable"

func main() {
	pool, err := pgxpool.New(context.TODO(), DB_URI)
	if err != nil {
		log.Fatalf("Error occured when opening a db connection\n%v", err)
		return
	}
	defer pool.Close()

	refreshTokenRepo := &auth.SQLRefreshTokenRepository{DB: pool}
	userRepo := &auth.SQLUserRepository{DB: pool}
	jwtProvider := &auth.JWTProvider{SecretKey: []byte(JWT_SECRET_KEY)}

	authService := auth.NewAuthService(
		REFRESH_TOKEN_EXPIRY,
		ACCESS_TOKEN_EXPIRY,
		refreshTokenRepo,
		jwtProvider,
	)
	userService := auth.NewUserService(userRepo, authService)

	server := api.NewServer(authService, userService)
	mux := server.Routes()

	log.Print("Listening...")
	err = http.ListenAndServe(":3000", mux)
	log.Fatal(err)
}
