package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost     = 12
	minPasswordLen = 8
)

func HashPassword(password string) (string, error) {
	if len(password) < minPasswordLen {
		return "", fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
