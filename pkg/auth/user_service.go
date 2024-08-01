package auth

type UserRepository interface {
	GetUserByCredentials(login string, password string) (User, error)
	GetUserByID(id UserID) (User, error)
	SaveUser(fullName string, login string, password string) error
}

type TokenProvider interface {
	CreateNewTokenPair(user *User) (access string, refresh string, err error)
}

type UserService struct {
	repo          UserRepository
	tokenProvider TokenProvider
}

func NewUserService(repo UserRepository, tokenProvider TokenProvider) *UserService {
	return &UserService{
		repo,
		tokenProvider,
	}
}

func (u *UserService) Login(login string, password string) (access string, refresh string, err error) {
	user, err := u.repo.GetUserByCredentials(login, password)
	if err != nil {
		return "", "", err
	}

	return u.tokenProvider.CreateNewTokenPair(&user)
}

func (u *UserService) Register(fullName string, login string, password string) error {
	return u.repo.SaveUser(fullName, login, password)
}

func (u *UserService) GetUserByID(id UserID) (User, error) {
	return u.repo.GetUserByID(id)
}
