import encryption from 'k6/x/encryption';
import { check } from 'k6';

export let options = {
    vus: 1,
    duration: '10s',
};

export default function () {
    console.log('=== k6 Encryption Extension Test ===');
    
    // Test 1: Generate and use a new key
    console.log('\n1. Testing key generation and basic encryption...');
    const key = encryption.GenerateQualifiedKey();
    console.log('Generated key:', key);
    
    const encryptor = encryption.NewEncryptor(key);
    
    // Test string encryption/decryption
    const originalText = "Hello from k6 encryption extension!";
    const encryptedText = encryptor.EncryptString(originalText);
    const decryptedText = encryptor.DecryptString(encryptedText);
    
    console.log('Original:', originalText);
    console.log('Encrypted (base64):', encryptedText);
    console.log('Decrypted:', decryptedText);
    
    check(null, {
        'String encryption/decryption works': () => originalText === decryptedText,
        'Encrypted text is different from original': () => encryptedText !== originalText,
        'Key is base64 encoded': () => key.length > 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(key)
    });
    
    // Test 2: Auto-switch decryption
    console.log('\n2. Testing auto-switch decryption...');
    const autoEncryptor = encryption.NewEncryptor(key);
    autoEncryptor.EnableAutoSwitchDecryption();
    
    // Test with encrypted data
    const secretMessage = "This is encrypted";
    const encrypted = autoEncryptor.EncryptString(secretMessage);
    const decrypted = autoEncryptor.DecryptString(encrypted);
    
    // Test with plain data (should return as-is)
    const plainMessage = "This is plain text";
    const plainResult = autoEncryptor.DecryptString(plainMessage);
    
    console.log('Auto-decrypt encrypted data:', decrypted);
    console.log('Auto-decrypt plain data:', plainResult);
    
    check(null, {
        'Auto-decrypt works with encrypted data': () => decrypted === secretMessage,
        'Auto-decrypt returns plain data as-is': () => plainResult === plainMessage
    });
    
    // Test 3: Binary data encryption
    console.log('\n3. Testing binary data encryption...');
    const binaryData = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);
    const encryptedBinary = encryptor.Encrypt(binaryData);
    const decryptedBinary = encryptor.Decrypt(encryptedBinary);
    
    console.log('Original binary length:', binaryData.length);
    console.log('Encrypted binary length:', encryptedBinary.length);
    console.log('Decrypted binary length:', decryptedBinary.length);
    
    // Compare arrays
    let binaryMatch = binaryData.length === decryptedBinary.length;
    if (binaryMatch) {
        for (let i = 0; i < binaryData.length; i++) {
            if (binaryData[i] !== decryptedBinary[i]) {
                binaryMatch = false;
                break;
            }
        }
    }
    
    check(null, {
        'Binary encryption/decryption works': () => binaryMatch,
        'Encrypted binary is longer (includes nonce)': () => encryptedBinary.length > binaryData.length
    });
    
    // Test 4: Multiple iterations (performance test)
    console.log('\n4. Testing performance with multiple operations...');
    const iterations = 100;
    const startTime = Date.now();
    
    for (let i = 0; i < iterations; i++) {
        const data = `Test message ${i}`;
        const enc = encryptor.EncryptString(data);
        const dec = encryptor.DecryptString(enc);
        
        if (dec !== data) {
            console.error(`Iteration ${i} failed!`);
            break;
        }
    }
    
    const endTime = Date.now();
    const totalTime = endTime - startTime;
    const avgTime = totalTime / iterations;
    
    console.log(`Completed ${iterations} encrypt/decrypt cycles`);
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Average time per cycle: ${avgTime.toFixed(2)}ms`);
    
    check(null, {
        'Performance test completed': () => totalTime > 0,
        'Average time per cycle < 10ms': () => avgTime < 10
    });
    
    console.log('\n=== Test completed successfully! ===');
}

// Setup function (runs once)
export function setup() {
    console.log('Setting up k6 encryption extension test...');
    return {};
}

// Teardown function (runs once)
export function teardown(data) {
    console.log('Tearing down k6 encryption extension test...');
}