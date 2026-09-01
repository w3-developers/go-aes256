package aes256

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func stringKeyToBytes(t *testing.T, sKey string) []byte {
	key, err := hex.DecodeString(sKey)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}

	return key
}

func TestAES256GCM_EncryptDecrypt(t *testing.T) {
	sKey := "c15c8b321d3fc4bfe309c558664477dfc0b42a757d008bb2a87815849c84ab03"
	key := stringKeyToBytes(t, sKey)

	aes256 := NewAES256GCM(key)

	plaintext := []byte("hello world")

	encrypted, err := aes256.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := aes256.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf(
			"Decrypt() = %q, want %q",
			decrypted,
			plaintext,
		)
	}
}

func TestAES256GCM_Encrypt_UsesRandomNonce(t *testing.T) {
	key := stringKeyToBytes(t, "c15c8b321d3fc4bfe309c558664477dfc0b42a757d008bb2a87815849c84ab03")

	aes256 := NewAES256GCM(key)

	plaintext := []byte("same plaintext")

	encrypted1, err := aes256.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("first Encrypt() error = %v", err)
	}

	encrypted2, err := aes256.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("second Encrypt() error = %v", err)
	}

	if bytes.Equal(encrypted1, encrypted2) {
		t.Fatal("expected different ciphertexts for same plaintext")
	}
}

func TestAES256GCM_Decrypt_InvalidData(t *testing.T) {
	key := stringKeyToBytes(t, "c15c8b321d3fc4bfe309c558664477dfc0b42a757d008bb2a87815849c84ab03")

	aes256 := NewAES256GCM(key)

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "nil",
			data: nil,
		},
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "too short",
			data: []byte{1, 2, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := aes256.Decrypt(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if err != ErrNonceOrCiphertextIsNil {
				t.Fatalf(
					"Decrypt() error = %v, want %v",
					err,
					ErrNonceOrCiphertextIsNil,
				)
			}
		})
	}
}

func TestAES256GCM_Decrypt_TamperedCiphertext(t *testing.T) {
	key := stringKeyToBytes(t, "c15c8b321d3fc4bfe309c558664477dfc0b42a757d008bb2a87815849c84ab03")

	aes256 := NewAES256GCM(key)

	plaintext := []byte("sensitive data")

	encrypted, err := aes256.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	encrypted[len(encrypted)-1] ^= 0xff

	_, err = aes256.Decrypt(encrypted)
	if err == nil {
		t.Fatal("expected authentication error, got nil")
	}
}

func TestAES256GCM_Decrypt_WithDifferentKey(t *testing.T) {
	key1 := stringKeyToBytes(t, "c15c8b321d3fc4bfe309c558664477dfc0b42a757d008bb2a87815849c84ab03")
	key2 := stringKeyToBytes(t, "44a5f271859a00406b36b94914ca8284a394060164b1418bb463af51c344da39")

	aes1 := NewAES256GCM(key1)
	aes2 := NewAES256GCM(key2)

	plaintext := []byte("hello")

	encrypted, err := aes1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	_, err = aes2.Decrypt(encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting with different key")
	}
}

func TestAES256GCM_Encrypt_EmptyPlaintext(t *testing.T) {
	key := stringKeyToBytes(t, "c15c8b321d3fc4bfe309c558664477dfc0b42a757d008bb2a87815849c84ab03")

	aes256 := NewAES256GCM(key)

	encrypted, err := aes256.Encrypt(nil)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := aes256.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("Decrypt() len = %d, want 0", len(decrypted))
	}
}
