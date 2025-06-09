# k6-encryption-extension

A k6 extension that provides AES-128-GCM encryption and decryption capabilities, with support for both standard and configurable custom formats.

## Features

- AES-128-GCM encryption and decryption
- Base64 key generation and handling
- Auto-switch decryption mode (attempts decryption, returns original data if it fails)
- String and byte array support
- Configurable custom AES-GCM format support

## Building

To build the extension, you'll need to use xk6:

```bash
# Install xk6 if you haven't already
go install go.k6.io/xk6/cmd/xk6@latest

# Build k6 with the encryption extension
xk6 build --with github.com/JBrVJxsc/xk6-encryption=.
```

This will create a `k6` binary with the encryption extension included.

## Usage

### Basic Encryption/Decryption

```javascript
import encryption from 'k6/x/encryption';

export default function () {
    // Generate a new encryption key
    const key = encryption.generateQualifiedKey();
    console.log('Generated key:', key);
    
    // Create an encryptor instance
    const encryptor = encryption.newEncryptor(key);
    
    // Encrypt a string
    const originalText = "Hello, World!";
    const encryptedText = encryptor.encryptString(originalText);
    console.log('Encrypted:', encryptedText);
    
    // Decrypt the string
    const decryptedText = encryptor.decryptString(encryptedText);
    console.log('Decrypted:', decryptedText);
    
    console.log('Original === Decrypted:', originalText === decryptedText);
}
```

### Working with Binary Data

```javascript
import encryption from 'k6/x/encryption';

export default function () {
    const key = encryption.generateQualifiedKey();
    const encryptor = encryption.newEncryptor(key);
    
    // Convert string to bytes
    const originalText = "This is binary data";
    const dataBytes = new Uint8Array(originalText.length);
    for (let i = 0; i < originalText.length; i++) {
        dataBytes[i] = originalText.charCodeAt(i);
    }
    
    // Encrypt binary data
    const encryptedBytes = encryptor.encrypt(dataBytes);
    console.log('Encrypted bytes length:', encryptedBytes.length);
    
    // Decrypt binary data
    const decryptedBytes = encryptor.decrypt(encryptedBytes);
    
    // Convert back to string
    let decryptedText = '';
    for (let i = 0; i < decryptedBytes.length; i++) {
        decryptedText += String.fromCharCode(decryptedBytes[i]);
    }
    
    console.log('Original === Decrypted:', originalText === decryptedText);
}
```

### Auto-Switch Decryption Mode

```javascript
import encryption from 'k6/x/encryption';

export default function () {
    const key = encryption.generateQualifiedKey();
    const encryptor = encryption.newEncryptor(key);
    
    // Enable auto-switch mode
    encryptor.enableAutoSwitchDecryption();
    
    // Test with encrypted data
    const encryptedData = encryptor.encryptString("Encrypted message");
    const result1 = encryptor.decryptString(encryptedData);
    console.log('Decrypted message:', result1);
    
    // Test with non-encrypted data (will return as-is)
    const plainData = "Plain text message";
    const result2 = encryptor.decryptString(plainData);
    console.log('Plain message returned as-is:', result2);
}
```

### Using Configurable Custom GCM Format

```javascript
import encryption from 'k6/x/encryption';

export default function () {
    const key = encryption.generateQualifiedKey();
    const encryptor = encryption.newEncryptor(key);
    
    // Configure custom format parameters
    const ivLength = 12;        // IV length in bytes (8-16)
    const validationOffset = 0; // Which byte of IV to use for validation (0-ivLength-1)
    
    // Use custom format: [ivLength-byte IV] + [validation byte] + [ciphertext + tag]
    const originalText = "Hello, Custom Format!";
    const textBytes = new Uint8Array(originalText.length);
    for (let i = 0; i < originalText.length; i++) {
        textBytes[i] = originalText.charCodeAt(i);
    }
    
    const encrypted = encryptor.encryptCustomGCMFormat(textBytes, ivLength, validationOffset);
    const decrypted = encryptor.decryptCustomGCMFormat(encrypted, ivLength, validationOffset);
    
    let decryptedText = '';
    for (let i = 0; i < decrypted.length; i++) {
        decryptedText += String.fromCharCode(decrypted[i]);
    }
    
    console.log('Original:', originalText);
    console.log('Decrypted:', decryptedText);
    console.log('Match:', originalText === decryptedText);
}
```

## API Reference

### JavaScript Naming Convention

In k6 extensions, Go methods are automatically converted from PascalCase to camelCase when used in JavaScript:

- `GenerateQualifiedKey()` (Go) → `generateQualifiedKey()` (JavaScript)
- `NewEncryptor()` (Go) → `newEncryptor()` (JavaScript)
- `EncryptString()` (Go) → `encryptString()` (JavaScript)

### Encryption Module

- `generateQualifiedKey()`: Generates a new base64-encoded AES-128 key
- `newEncryptor(key)`: Creates a new Encryptor instance with the provided base64 key

### Encryptor Methods

- `encrypt(data)`: Encrypts byte array data using standard GCM format
- `decrypt(data)`: Decrypts byte array data using standard GCM format
- `encryptString(text)`: Encrypts a string and returns base64-encoded result
- `decryptString(encodedData)`: Decrypts base64-encoded data and returns string
- `encryptCustomGCMFormat(data, ivLength, validationOffset)`: Encrypts data using configurable custom format
- `decryptCustomGCMFormat(data, ivLength, validationOffset)`: Decrypts data from configurable custom format
- `enableAutoSwitchDecryption()`: Enables auto-switch mode for decryption
- `isEncryptionEnabled()`: Always returns true for this implementation

## Custom Format Parameters

- `ivLength`: Length of the initialization vector in bytes (8-16)
- `validationOffset`: Index within the IV to use for validation byte (0 to ivLength-1)

The custom format structure is: `[IV] + [IV[validationOffset]] + [ciphertext + tag]`

## Compatibility

This extension is compatible with Java AES-GCM implementations that use standard and custom formats. Keys and encrypted data can be exchanged between compatible Java implementations and this k6 extension.

## Requirements

- Go 1.21 or later
- k6 v0.47.0 or later
- xk6 for building

## License

This extension is provided as-is for testing and development purposes.