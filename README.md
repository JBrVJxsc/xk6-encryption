# k6-encryption-extension

A k6 extension that provides AES-128-GCM encryption and decryption capabilities, compatible with the Coupang encryption service implementation.

## Features

- AES-128-GCM encryption and decryption
- Base64 key generation and handling
- Auto-switch decryption mode (attempts decryption, returns original data if it fails)
- String and byte array support
- Compatible with Java implementation using AES128GCMCipher

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
    const key = encryption.GenerateQualifiedKey();
    console.log('Generated key:', key);
    
    // Create an encryptor instance
    const encryptor = encryption.NewEncryptor(key);
    
    // Encrypt a string
    const originalText = "Hello, World!";
    const encryptedText = encryptor.EncryptString(originalText);
    console.log('Encrypted:', encryptedText);
    
    // Decrypt the string
    const decryptedText = encryptor.DecryptString(encryptedText);
    console.log('Decrypted:', decryptedText);
    
    console.log('Original === Decrypted:', originalText === decryptedText);
}
```

### Working with Binary Data

```javascript
import encryption from 'k6/x/encryption';
import encoding from 'k6/encoding';

export default function () {
    const key = encryption.GenerateQualifiedKey();
    const encryptor = encryption.NewEncryptor(key);
    
    // Convert string to bytes
    const originalData = encoding.b64encode("This is binary data");
    const dataBytes = encoding.b64decode(originalData);
    
    // Encrypt binary data
    const encryptedBytes = encryptor.Encrypt(dataBytes);
    console.log('Encrypted bytes length:', encryptedBytes.length);
    
    // Decrypt binary data
    const decryptedBytes = encryptor.Decrypt(encryptedBytes);
    const decryptedText = encoding.b64encode(decryptedBytes);
    
    console.log('Original === Decrypted:', originalData === decryptedText);
}
```

### Auto-Switch Decryption Mode

```javascript
import encryption from 'k6/x/encryption';

export default function () {
    const key = encryption.GenerateQualifiedKey();
    const encryptor = encryption.NewEncryptor(key);
    
    // Enable auto-switch mode
    encryptor.EnableAutoSwitchDecryption();
    
    // Test with encrypted data
    const encryptedData = encryptor.EncryptString("Encrypted message");
    const result1 = encryptor.DecryptString(encryptedData);
    console.log('Decrypted message:', result1);
    
    // Test with non-encrypted data (will return as-is)
    const plainData = "Plain text message";
    const result2 = encryptor.DecryptString(plainData);
    console.log('Plain message returned as-is:', result2);
}
```

### Using with HTTP Requests

```javascript
import http from 'k6/http';
import encryption from 'k6/x/encryption';

export default function () {
    const key = "your-base64-encoded-key-here";
    const encryptor = encryption.NewEncryptor(key);
    
    // Encrypt payload before sending
    const payload = JSON.stringify({
        userId: 12345,
        message: "Secret message"
    });
    
    const encryptedPayload = encryptor.EncryptString(payload);
    
    // Send encrypted data
    const response = http.post('https://api.example.com/encrypted', {
        data: encryptedPayload
    }, {
        headers: {
            'Content-Type': 'application/json',
            'X-Encryption': 'AES128GCM'
        }
    });
    
    // Decrypt response if needed
    if (response.headers['X-Encrypted'] === 'true') {
        const decryptedResponse = encryptor.DecryptString(response.body);
        console.log('Decrypted response:', decryptedResponse);
    }
}
```

### Load Testing Encrypted APIs

```javascript
import http from 'k6/http';
import encryption from 'k6/x/encryption';
import { check } from 'k6';

export let options = {
    stages: [
        { duration: '30s', target: 10 },
        { duration: '1m', target: 50 },
        { duration: '30s', target: 0 },
    ],
};

const encryptionKey = "your-shared-encryption-key";

export default function () {
    const encryptor = encryption.NewEncryptor(encryptionKey);
    
    // Prepare test data
    const testData = {
        timestamp: Date.now(),
        userId: Math.floor(Math.random() * 10000),
        action: 'test_action'
    };
    
    // Encrypt the payload
    const encryptedData = encryptor.EncryptString(JSON.stringify(testData));
    
    // Send encrypted request
    const response = http.post('https://your-api.com/secure-endpoint', {
        payload: encryptedData
    });
    
    // Verify response
    check(response, {
        'status is 200': (r) => r.status === 200,
        'response time < 500ms': (r) => r.timings.duration < 500,
    });
    
    // Decrypt response if encrypted
    if (response.headers['content-encryption'] === 'enabled') {
        const decryptedResponse = encryptor.DecryptString(response.body);
        const responseData = JSON.parse(decryptedResponse);
        
        check(responseData, {
            'response contains success': (data) => data.status === 'success',
        });
    }
}
```

## API Reference

### Encryption Module

- `GenerateQualifiedKey()`: Generates a new base64-encoded AES-128 key
- `NewEncryptor(key)`: Creates a new Encryptor instance with the provided base64 key

### Encryptor Methods

- `Encrypt(data)`: Encrypts byte array data
- `Decrypt(data)`: Decrypts byte array data
- `EncryptString(text)`: Encrypts a string and returns base64-encoded result
- `DecryptString(encodedData)`: Decrypts base64-encoded data and returns string
- `EnableAutoSwitchDecryption()`: Enables auto-switch mode for decryption
- `IsEncryptionEnabled()`: Always returns true for this implementation

## Compatibility

This extension is compatible with the Java AES128GCMCipher implementation used in the Coupang service. Keys and encrypted data can be exchanged between the Java implementation and this k6 extension.

## Requirements

- Go 1.24.2 or later
- k6 v0.47.0 or later
- xk6 for building

## License

This extension is provided as-is for testing and development purposes.