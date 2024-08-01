package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

/*
CREATE TABLE tokens (
	id SERIAL PRIMARY KEY,
	token CHAR(64) NOT NULL,
	user_id INT REFERENCES users(id) ON DELETE CASCADE,
	expires_at timestamptz NOT NULL
);
CREATE INDEX idx_tokens_token ON tokens(token);
*/

type SQLRefreshTokenRepository struct {
	DB *pgxpool.Pool
}

const TOKEN_BYTE_LENGTH = 48
const TOKEN_STRING_LENGTH = TOKEN_BYTE_LENGTH / 3 * 4 // base64 encoded

func (r *SQLRefreshTokenRepository) CreateToken(userID UserID, expiry time.Duration) (tokenID RefreshToken, err error) {
	query := "INSERT INTO tokens (token, user_id, expires_at) VALUES ($1, $2, $3)"
	expiresAt := time.Now().Add(expiry)
	tokenStr := generateToken()
	_, err = r.DB.Exec(context.TODO(), query, tokenStr, userID, expiresAt)
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

func (r *SQLRefreshTokenRepository) UpdateTokenAndGetUserID(token RefreshToken, expiry time.Duration) (RefreshToken, UserID, error) {
	newToken := generateToken()
	query := "UPDATE tokens SET token=$1, expires_at=$2 WHERE token=$3 RETURNING user_id"
	expiresAt := time.Now().Add(expiry)
	row := r.DB.QueryRow(context.TODO(), query, newToken, expiresAt, token)
	var userID UserID
	err := row.Scan(&userID)
	if err != nil {
		return "", 0, err
	}
	return newToken, userID, nil
}

func (r *SQLRefreshTokenRepository) RevokeToken(token RefreshToken) error {
	_, err := r.DB.Exec(context.TODO(), "DELETE FROM tokens WHERE id=$1", token)
	return err
}

func generateToken() RefreshToken {
	bytes := make([]byte, TOKEN_BYTE_LENGTH)
	rand.Read(bytes)
	return RefreshToken(base64.URLEncoding.EncodeToString(bytes))
}

func (r *SQLRefreshTokenRepository) NewTokenFromString(tokenStr string) (RefreshToken, error) {
	if len(tokenStr) != TOKEN_STRING_LENGTH {
		return "", errors.New("invalid token")
	}
	return RefreshToken(tokenStr), nil
}
