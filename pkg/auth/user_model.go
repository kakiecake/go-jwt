package auth

type UserID int64

type User struct {
	Login          string
	FullName       string
	hashedPassword string
	ID             UserID
}
