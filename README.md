# API specification

## Main endpoints

- /public endpoint available to everyone, returns something
- /me endpoint, that returns information about the current user

## Authorization endpoints
- /register registers a user
- /login authorizes a user with login/password combination, returns access + refresh token pair
- /token fetches new access + refresh token pair using a refresh token
- /revoke revokes a refresh token

## Rules
- Refresh tokens must be stored inside a database
- PostgreSQL must be used as a database
- Go must be used a language of choice
- Access token must be a JWT

