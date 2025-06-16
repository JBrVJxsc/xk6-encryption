package encryption

import (
	"encoding/base64"
	"testing"
)

func TestNewEncryptor(t *testing.T) {
	// Test with valid key
	key, err := new(Encryption).GenerateQualifiedKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	enc, err := new(Encryption).NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}
	if enc == nil {
		t.Fatal("Encryptor should not be nil")
	}

	// Test with empty key
	_, err = new(Encryption).NewEncryptor("")
	if err == nil {
		t.Error("Expected error for empty key")
	}

	// Test with invalid base64
	_, err = new(Encryption).NewEncryptor("invalid-base64")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	// Test with wrong key length
	shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = new(Encryption).NewEncryptor(shortKey)
	if err == nil {
		t.Error("Expected error for wrong key length")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := new(Encryption).GenerateQualifiedKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	enc, err := new(Encryption).NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", []byte(""), ""},
		{"simple", []byte("hello world"), "hello world"},
		{"special chars", []byte("!@#$%^&*()"), "!@#$%^&*()"},
		{"unicode", []byte("你好世界"), "你好世界"},
		{"long text", []byte("This is a very long text that needs to be encrypted and decrypted properly. It should work without any issues."), "This is a very long text that needs to be encrypted and decrypted properly. It should work without any issues."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test byte array encryption/decryption
			encrypted, err := enc.Encrypt(tc.input)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := enc.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != string(tc.input) {
				t.Errorf("Decrypted data doesn't match input. Got: %s, Want: %s", decrypted, tc.input)
			}

			// Test string encryption/decryption
			encryptedStr, err := enc.EncryptString(string(tc.input))
			if err != nil {
				t.Fatalf("String encryption failed: %v", err)
			}

			decryptedStr, err := enc.DecryptString(encryptedStr)
			if err != nil {
				t.Fatalf("String decryption failed: %v", err)
			}

			if decryptedStr != string(tc.input) {
				t.Errorf("Decrypted string doesn't match input. Got: %s, Want: %s", decryptedStr, tc.input)
			}
		})
	}
}

func TestAutoSwitchDecryption(t *testing.T) {
	key, err := new(Encryption).GenerateQualifiedKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	enc, err := new(Encryption).NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Enable auto-switch decryption
	enc.EnableAutoSwitchDecryption()

	// Test with encrypted data
	plaintext := "test message"
	encrypted, err := enc.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := enc.DecryptString(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt encrypted data: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Decrypted data doesn't match. Got: %s, Want: %s", decrypted, plaintext)
	}

	// Test with plain text
	plaintext = "plain text message"
	decrypted, err = enc.DecryptString(plaintext)
	if err != nil {
		t.Fatalf("Failed to handle plain text: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Plain text was modified. Got: %s, Want: %s", decrypted, plaintext)
	}
}

func TestCustomGCMFormat(t *testing.T) {
	key, err := new(Encryption).GenerateQualifiedKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	enc, err := new(Encryption).NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	testCases := []struct {
		name             string
		input            []byte
		ivLength         int
		validationOffset int
	}{
		{"standard", []byte("test message"), 12, 0},
		{"short iv", []byte("test message"), 8, 4},
		{"long iv", []byte("test message"), 16, 8},
		{"empty", []byte(""), 12, 0},
		{"long text", []byte("This is a very long text that needs to be encrypted and decrypted properly."), 12, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := enc.EncryptCustomGCMFormat(tc.input, tc.ivLength, tc.validationOffset)
			if err != nil {
				t.Fatalf("Custom format encryption failed: %v", err)
			}

			decrypted, err := enc.DecryptCustomGCMFormat(encrypted, tc.ivLength, tc.validationOffset)
			if err != nil {
				t.Fatalf("Custom format decryption failed: %v", err)
			}

			if string(decrypted) != string(tc.input) {
				t.Errorf("Decrypted data doesn't match input. Got: %s, Want: %s", decrypted, tc.input)
			}
		})
	}

	// Test invalid parameters
	invalidCases := []struct {
		name             string
		ivLength         int
		validationOffset int
	}{
		{"iv too short", 7, 0},
		{"iv too long", 17, 0},
		{"negative offset", 12, -1},
		{"offset too large", 12, 12},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := enc.EncryptCustomGCMFormat([]byte("test"), tc.ivLength, tc.validationOffset)
			if err == nil {
				t.Error("Expected error for invalid parameters")
			}
		})
	}
}

func TestGenerateQualifiedKey(t *testing.T) {
	enc := new(Encryption)

	// Generate multiple keys and verify they're different
	key1, err := enc.GenerateQualifiedKey()
	if err != nil {
		t.Fatalf("Failed to generate first key: %v", err)
	}

	key2, err := enc.GenerateQualifiedKey()
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}

	if key1 == key2 {
		t.Error("Generated keys should be different")
	}

	// Verify key format
	keyBytes, err := base64.StdEncoding.DecodeString(key1)
	if err != nil {
		t.Fatalf("Failed to decode generated key: %v", err)
	}

	if len(keyBytes) != 16 {
		t.Errorf("Generated key should be 16 bytes, got %d", len(keyBytes))
	}
}
