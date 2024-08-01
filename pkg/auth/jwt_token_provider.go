package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTProvider struct {
	SecretKey []byte
}

func (p *JWTProvider) CreateToken(data *TokenData) (string, error) {
	claims := jwt.MapClaims{"uid": data.UserID, "iat": time.Now().Unix(), "exp": data.ExpiresAt.Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(p.SecretKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (p *JWTProvider) ParseToken(tokenStr string) (*TokenData, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		return p.SecretKey, nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, ErrExpired
	}
	if err != nil {
		return nil, err
	}
	token := TokenData{
		UserID:    UserID(claims["uid"].(float64)),
		ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
	}
	return &token, nil
}
