package ecdh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// SharedSecret shared by ECDH secret
type SharedSecret struct {
	Secret string
	gcm    cipher.AEAD
}

// NewSharedSecret create new SharedSecret by raw secret
func NewSharedSecret(secret string) (*SharedSecret, error) {
	cphr, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("NewCipher: %v", err)
	}

	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return nil, fmt.Errorf("NewGCM: %v", err)
	}

	SharedSecret := &SharedSecret{Secret: secret, gcm: gcm}

	return SharedSecret, nil
}

// Encrypt encrypt message with a shared secret by AES
func (secret *SharedSecret) Encrypt(message string) (string, error) {
	nonce := make([]byte, secret.nonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("io.ReadFull: %v", err)
	}

	return secret.seal(nonce, message), nil
}

// Decrypt decrypt message with a shared secret by AES
func (secret *SharedSecret) Decrypt(encrypted string) (string, error) {
	nonceSize := secret.nonceSize()
	if len(encrypted) < nonceSize {
		return "", fmt.Errorf("Invalid NonceSize")
	}

	nonce, encryptedMessage := encrypted[:nonceSize], encrypted[nonceSize:]
	message, err := secret.open(nonce, encryptedMessage)
	if err != nil {
		return "", fmt.Errorf("Decrypt: %v", err)
	}

	return string(message), nil
}

func (secret *SharedSecret) nonceSize() int {
	return secret.gcm.NonceSize()
}

func (secret *SharedSecret) seal(nonce []byte, message string) string {
	return string(secret.gcm.Seal(nonce, nonce, []byte(message), nil))
}

func (secret *SharedSecret) open(nonce, message string) ([]byte, error) {
	return secret.gcm.Open(nil, []byte(nonce), []byte(message), nil)
}
