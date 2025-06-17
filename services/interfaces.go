package services

// PasswordHasher defines an interface for hashing and verifying passwords.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hashedPassword, password string) error
}
