package auth

import (
	"context"
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type SQLUserRepository struct {
	DB *pgxpool.Pool
}

var ErrNoUser = errors.New("no user found")
var ErrUserExists = errors.New("user already exists")

func (r *SQLUserRepository) GetUserByID(id UserID) (User, error) {
	query := "SELECT id, login, full_name, hashed_password FROM users WHERE id=$1"
	row := r.DB.QueryRow(context.TODO(), query, id)
	user := User{}
	err := row.Scan(&user.ID, &user.Login, &user.FullName, &user.hashedPassword)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (r *SQLUserRepository) GetUserByCredentials(login string, password string) (User, error) {
	query := "SELECT id, login, full_name, hashed_password FROM users WHERE login=$1"
	row := r.DB.QueryRow(context.TODO(), query, login)

	user := User{}
	err := row.Scan(&user.ID, &user.Login, &user.FullName, &user.hashedPassword)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNoUser
	}
	if err != nil {
		return User{}, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.hashedPassword), []byte(password))
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (r *SQLUserRepository) SaveUser(fullName string, login string, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	query := "INSERT INTO users (login, full_name, hashed_password) values ($1, $2, $3)"
	_, err = r.DB.Exec(context.TODO(), query, login, fullName, hashedPassword)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return ErrUserExists
	}
	if err != nil {
		return err
	}

	return nil
}
