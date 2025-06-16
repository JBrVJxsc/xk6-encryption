package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

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

	// Performance optimizations: Pre-computed cipher instances
	aeadGCM cipher.AEAD
	block   cipher.Block

	// Buffer pools for reusing memory
	noncePool sync.Pool
}

// Buffer pool helpers
func (enc *Encryptor) getNonceBuffer() []byte {
	if buf := enc.noncePool.Get(); buf != nil {
		return *(buf.(*[]byte))
	}
	return make([]byte, 12) // GCM nonce size
}

func (enc *Encryptor) putNonceBuffer(buf []byte) {
	if len(buf) == 12 {
		// Clear for security before returning to pool
		for i := range buf {
			buf[i] = 0
		}
		enc.noncePool.Put(&buf)
	}
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

	// Pre-create cipher instances for performance
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aeadGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	enc := &Encryptor{
		keyBytes:               keyBytes,
		autoSwitchDecryption:   false,
		expectEncryptedMessage: nil,
		aeadGCM:                aeadGCM,
		block:                  block,
	}

	// Initialize buffer pools
	enc.noncePool = sync.Pool{
		New: func() any {
			nonce := make([]byte, 12)
			return &nonce
		},
	}

	return enc, nil
}

// Encrypt encrypts the provided data using AES-128-GCM
func (enc *Encryptor) Encrypt(data []byte) ([]byte, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	// Get nonce buffer from pool
	nonce := enc.getNonceBuffer()
	defer enc.putNonceBuffer(nonce)

	// Generate random nonce
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data using pre-computed GCM instance
	ciphertext := enc.aeadGCM.Seal(nonce, nonce, data, nil)
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
	nonceSize := enc.aeadGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := enc.aeadGCM.Open(nil, nonce, ciphertext, nil)
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
	// If auto-switch decryption is enabled, handle potential plain text input
	if enc.autoSwitchDecryption {
		// Try to decode as base64 first
		data, err := base64.StdEncoding.DecodeString(encodedData)
		if err != nil {
			// If base64 decoding fails and auto-switch is enabled, return original string
			enc.optionalLog(false)
			return encodedData, nil
		}

		// Try to decrypt the decoded data
		decrypted, err := enc.Decrypt(data)
		if err != nil {
			// If decryption fails and auto-switch is enabled, return original string
			enc.optionalLog(false)
			return encodedData, nil
		}

		enc.optionalLog(true)
		return string(decrypted), nil
	}

	// Normal mode: require valid base64 input
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
	// Get nonce buffer from pool
	gcmNonce := enc.getNonceBuffer()
	defer enc.putNonceBuffer(gcmNonce)

	// Clear the nonce buffer first for security
	for i := range gcmNonce {
		gcmNonce[i] = 0
	}

	// If stored IV is not 12 bytes, we need to adjust it
	if ivLength == 12 {
		copy(gcmNonce, storedIV)
	} else if ivLength < 12 {
		// Pad with zeros to reach 12 bytes (must match encryption logic)
		copy(gcmNonce, storedIV)
		// Rest remains zero-padded
	} else {
		// Truncate to 12 bytes
		copy(gcmNonce, storedIV[:12])
	}

	// Decrypt using pre-created GCM instance (encryptedData already contains ciphertext + tag)
	plaintext, err := enc.aeadGCM.Open(nil, gcmNonce, encryptedData, nil)
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

	// Get nonce buffer from pool
	gcmNonce := enc.getNonceBuffer()
	defer enc.putNonceBuffer(gcmNonce)

	// Generate a random 12-byte nonce (GCM requirement)
	if _, err := rand.Read(gcmNonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create the IV to store in the format
	var storedIV []byte
	var actualNonce []byte

	if ivLength == 12 {
		storedIV = make([]byte, 12)
		copy(storedIV, gcmNonce)
		actualNonce = gcmNonce
	} else if ivLength < 12 {
		// Use first ivLength bytes of the nonce and pad with zeros for actual encryption
		// This ensures decryption can reconstruct the same nonce by padding with zeros
		storedIV = make([]byte, ivLength)
		copy(storedIV, gcmNonce[:ivLength])

		// Clear the nonce buffer and copy back the truncated IV for encryption
		for i := range gcmNonce {
			gcmNonce[i] = 0
		}
		copy(gcmNonce, storedIV)
		actualNonce = gcmNonce
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
	encryptedData := enc.aeadGCM.Seal(nil, actualNonce, data, nil)

	// Create custom format: [stored IV] + [validation byte] + [ciphertext + tag]
	resultSize := ivLength + 1 + len(encryptedData)
	result := make([]byte, 0, resultSize)
	result = append(result, storedIV...)                // Add stored IV
	result = append(result, storedIV[validationOffset]) // Add validation byte
	result = append(result, encryptedData...)           // Add encrypted data + tag

	return result, nil
}
