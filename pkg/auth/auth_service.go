package auth

import (
	"errors"
	"time"
)

// refresh token is stored in database, but used as a JWT
// it has a "Refresh" claim and a user id assigned to it
// when a new access + refresh pair is requested, refresh token is checked in database

type TokenKind string

const (
	ACCESS_TOKEN  = "access"
	REFRESH_TOKEN = "refresh"
)

type RefreshTokenRepository interface {
	NewTokenFromString(tokenStr string) (RefreshToken, error)
	CreateToken(userID UserID, expiry time.Duration) (RefreshToken, error)
	UpdateTokenAndGetUserID(tokenStr RefreshToken, expiry time.Duration) (RefreshToken, UserID, error)
	RevokeToken(tokenStr RefreshToken) error
}

func NewAuthService(
	refreshTokenExpiry time.Duration,
	accessTokenExpiry time.Duration,
	repo RefreshTokenRepository,
	tokenCreator TokenCreator,
) *AuthService {
	return &AuthService{
		repo:               repo,
		tokenCreator:       tokenCreator,
		refreshTokenExpiry: refreshTokenExpiry,
		accessTokenExpiry:  accessTokenExpiry,
	}
}

type AuthService struct {
	repo               RefreshTokenRepository
	tokenCreator       TokenCreator
	refreshTokenExpiry time.Duration
	accessTokenExpiry  time.Duration
}

func (a *AuthService) RefreshTokenExpirySec() int {
	return int(a.refreshTokenExpiry.Seconds())
}

func (a *AuthService) AccessTokenExpirySec() int {
	return int(a.accessTokenExpiry.Seconds())
}

// what data does a token store?
// -> userId, claims (access rights), expiry (not business logic)

type TokenData struct {
	ExpiresAt time.Time
	UserID    UserID
}

func (t *TokenData) Kind() TokenKind {
	return ACCESS_TOKEN
}

func NewAccessToken(userID UserID, expiry time.Duration) TokenData {
	return TokenData{UserID: userID, ExpiresAt: time.Now().Add(expiry)}
}

var ErrExpired = errors.New("token expired")
var ErrInvalidToken = errors.New("invalid token")

type TokenCreator interface {
	CreateToken(token *TokenData) (string, error)
	ParseToken(tokenStr string) (*TokenData, error)
}

// access token
// userId, access claims -> jwt signed token
// refresh token
// userId, tokenId,

// Two scenarios for refresh tokens
// 1) create new token pair (from scratch)
// 2) update existing refresh token, get new pair

func (a *AuthService) CreateNewTokenPair(user *User) (access string, refresh string, err error) {
	refreshTokenID, err := a.repo.CreateToken(user.ID, a.refreshTokenExpiry)
	if err != nil {
		return "", "", err
	}
	accessTokenData := NewAccessToken(user.ID, a.accessTokenExpiry)
	access, err = a.tokenCreator.CreateToken(&accessTokenData)
	if err != nil {
		return "", "", err
	}
	return access, string(refreshTokenID), err
}

func (a *AuthService) UpdateTokenPair(tokenStr string) (access string, refresh string, err error) {
	refreshToken, err := a.repo.NewTokenFromString(tokenStr)
	if err != nil {
		return "", "", ErrInvalidToken
	}
	newRefreshToken, userID, err := a.repo.UpdateTokenAndGetUserID(refreshToken, a.refreshTokenExpiry)
	if err != nil {
		return "", "", nil
	}
	tokenData := NewAccessToken(userID, a.accessTokenExpiry)
	accessToken, err := a.tokenCreator.CreateToken(&tokenData)
	if err != nil {
		return "", "", err
	}

	return accessToken, string(newRefreshToken), nil
}

func (a *AuthService) RevokeRefreshToken(refreshToken string) error {
	err := a.repo.RevokeToken(RefreshToken(refreshToken))
	if err != nil {
		return err
	}

	return nil
}

func (a *AuthService) GetUserIDFromToken(tokenStr string) (UserID, error) {
	token, err := a.tokenCreator.ParseToken(tokenStr)
	if err != nil {
		return 0, err
	}
	return token.UserID, nil
}
