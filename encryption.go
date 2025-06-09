package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/encryption", new(Encryption))
}

// Encryption is the main module that will be exposed to k6 JavaScript
type Encryption struct{}

// Encryptor holds the encryption state and configuration
type Encryptor struct {
	keyBytes               []byte
	autoSwitchDecryption   bool
	expectEncryptedMessage *bool
}

// NewEncryptor creates a new Encryptor instance with the provided base64 encoded key
func (*Encryption) NewEncryptor(key string) (*Encryptor, error) {
	if key == "" {
		return nil, errors.New("key cannot be empty")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %w", err)
	}

	if len(keyBytes) != 16 {
		return nil, errors.New("key must be 16 bytes (128 bits) for AES-128")
	}

	return &Encryptor{
		keyBytes:               keyBytes,
		autoSwitchDecryption:   false,
		expectEncryptedMessage: nil,
	}, nil
}

// Encrypt encrypts the provided data using AES-128-GCM
func (enc *Encryptor) Encrypt(data []byte) ([]byte, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	block, err := aes.NewCipher(enc.keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts the provided data using AES-128-GCM
func (enc *Encryptor) Decrypt(data []byte) ([]byte, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	if enc.autoSwitchDecryption {
		return enc.tryDecrypt(data)
	}

	return enc.decryptInternal(data)
}

// decryptInternal performs the actual decryption
func (enc *Encryptor) decryptInternal(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(enc.keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// tryDecrypt attempts to decrypt data, returns original data if decryption fails
func (enc *Encryptor) tryDecrypt(data []byte) ([]byte, error) {
	decryptedData, err := enc.decryptInternal(data)
	if err == nil && len(decryptedData) > 0 {
		enc.optionalLog(true)
		return decryptedData, nil
	}

	enc.optionalLog(false)
	return data, nil
}

// optionalLog mimics the Java logging behavior
func (enc *Encryptor) optionalLog(messageEncrypted bool) {
	if messageEncrypted {
		if enc.expectEncryptedMessage == nil || !*enc.expectEncryptedMessage {
			expectTrue := true
			enc.expectEncryptedMessage = &expectTrue
			fmt.Println("WARN: autoSwitchDecryption is on and Encrypted message has been got.")
		}
	} else {
		if enc.expectEncryptedMessage == nil || *enc.expectEncryptedMessage {
			expectFalse := false
			enc.expectEncryptedMessage = &expectFalse
			fmt.Println("WARN: autoSwitchDecryption is on and Non-encrypted message has been got.")
		}
	}
}

// EnableAutoSwitchDecryption enables automatic switching between encrypted and non-encrypted messages
func (enc *Encryptor) EnableAutoSwitchDecryption() {
	enc.autoSwitchDecryption = true
}

// IsEncryptionEnabled returns whether encryption is enabled (always true for this implementation)
func (enc *Encryptor) IsEncryptionEnabled() bool {
	return true
}

// GenerateQualifiedKey generates a new base64 encoded AES-128 key
func (*Encryption) GenerateQualifiedKey() (string, error) {
	key := make([]byte, 16) // 128 bits
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// EncryptString is a convenience method for encrypting strings
func (enc *Encryptor) EncryptString(text string) (string, error) {
	encrypted, err := enc.Encrypt([]byte(text))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptString is a convenience method for decrypting base64 encoded strings
func (enc *Encryptor) DecryptString(encodedData string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 data: %w", err)
	}

	decrypted, err := enc.Decrypt(data)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// DecryptCustomGCMFormat decrypts data in a configurable custom AES-GCM format
// Format: [ivLength-byte IV] + [validationByte] + [ciphertext + tag]
// Note: GCM always uses 12-byte nonce internally, ivLength controls format storage
func (enc *Encryptor) DecryptCustomGCMFormat(data []byte, ivLength int, validationOffset int) ([]byte, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	if ivLength < 8 || ivLength > 16 {
		return nil, errors.New("IV length must be between 8 and 16 bytes")
	}

	if validationOffset < 0 || validationOffset >= ivLength {
		return nil, errors.New("validation offset must be within IV range")
	}

	block, err := aes.NewCipher(enc.keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	minDataLength := ivLength + 1 + 16 // IV + validation byte + minimum tag size

	if len(data) < minDataLength {
		return nil, fmt.Errorf("data too short for custom format, need at least %d bytes, got %d", minDataLength, len(data))
	}

	// Extract components according to custom format
	storedIV := data[:ivLength]
	validationByte := data[ivLength]
	encryptedData := data[ivLength+1:]

	// Validate the format
	if storedIV[validationOffset] != validationByte {
		return nil, fmt.Errorf("invalid custom format: validation byte %02x doesn't match IV[%d] %02x", validationByte, validationOffset, storedIV[validationOffset])
	}

	// GCM always needs exactly 12 bytes for nonce
	// If stored IV is not 12 bytes, we need to adjust it
	var gcmNonce []byte
	if ivLength == 12 {
		gcmNonce = storedIV
	} else if ivLength < 12 {
		// Pad with zeros to reach 12 bytes (must match encryption logic)
		gcmNonce = make([]byte, 12)
		copy(gcmNonce, storedIV)
	} else {
		// Truncate to 12 bytes
		gcmNonce = storedIV[:12]
	}

	// Decrypt using standard GCM (encryptedData already contains ciphertext + tag)
	plaintext, err := gcm.Open(nil, gcmNonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt custom GCM format: %w", err)
	}

	return plaintext, nil
}

// EncryptCustomGCMFormat encrypts data to match a configurable custom AES-GCM format
// Format: [ivLength-byte IV] + [validationByte] + [ciphertext + tag]
// Note: GCM always uses 12-byte nonce internally, ivLength controls format storage
func (enc *Encryptor) EncryptCustomGCMFormat(data []byte, ivLength int, validationOffset int) ([]byte, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	if ivLength < 8 || ivLength > 16 {
		return nil, errors.New("IV length must be between 8 and 16 bytes")
	}

	if validationOffset < 0 || validationOffset >= ivLength {
		return nil, errors.New("validation offset must be within IV range")
	}

	block, err := aes.NewCipher(enc.keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random 12-byte nonce (GCM requirement)
	gcmNonce := make([]byte, 12)
	if _, err := rand.Read(gcmNonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create the IV to store in the format and the actual nonce to use for encryption
	var storedIV []byte
	var actualNonce []byte

	if ivLength == 12 {
		storedIV = gcmNonce
		actualNonce = gcmNonce
	} else if ivLength < 12 {
		// Use first ivLength bytes of the nonce and pad with zeros for actual encryption
		// This ensures decryption can reconstruct the same nonce by padding with zeros
		storedIV = gcmNonce[:ivLength]
		actualNonce = make([]byte, 12)
		copy(actualNonce, storedIV)
		// Rest remains zero-padded
	} else {
		// Generate additional random bytes to reach ivLength
		storedIV = make([]byte, ivLength)
		copy(storedIV, gcmNonce) // First 12 bytes from nonce
		if _, err := rand.Read(storedIV[12:]); err != nil {
			return nil, fmt.Errorf("failed to generate additional IV bytes: %w", err)
		}
		actualNonce = gcmNonce // Use original nonce (first 12 bytes of storedIV)
	}

	// Encrypt the data using the actual nonce (returns ciphertext + tag combined)
	encryptedData := gcm.Seal(nil, actualNonce, data, nil)

	// Create custom format: [stored IV] + [validation byte] + [ciphertext + tag]
	result := make([]byte, 0, ivLength+1+len(encryptedData))
	result = append(result, storedIV...)                // Add stored IV
	result = append(result, storedIV[validationOffset]) // Add validation byte
	result = append(result, encryptedData...)           // Add encrypted data + tag

	return result, nil
}
