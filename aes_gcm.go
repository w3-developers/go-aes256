package aes256

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	ErrNonceOrCiphertextIsNil = errors.New("nonce or ciphertext is nil")
)

type AES256GCM struct {
	key []byte
}

func NewAES256GCM(key []byte) *AES256GCM {
	return &AES256GCM{key: key}
}

func (a *AES256GCM) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

func (a *AES256GCM) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrNonceOrCiphertextIsNil
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
