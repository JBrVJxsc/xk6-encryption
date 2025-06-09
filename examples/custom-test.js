import encryption from 'k6/x/encryption';
import { check } from 'k6';

export let options = {
    vus: 1,
    duration: '10s',
};

// Helper function to convert string to bytes
function stringToBytes(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
    }
    return bytes;
}

// Helper function to convert bytes to string
function bytesToString(bytes) {
    let str = '';
    for (let i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return str;
}

// Generate random test parameters
function getRandomTestParams() {
    const ivLength = Math.floor(Math.random() * 9) + 8; // 8-16 bytes
    const validationOffset = Math.floor(Math.random() * ivLength); // 0 to ivLength-1
    return { ivLength, validationOffset };
}

export default function () {
    console.log('=== k6 Encryption Extension Custom Format Test ===');
    
    // Generate a key for testing
    const key = encryption.generateQualifiedKey();
    const encryptor = encryption.newEncryptor(key);
    
    // Test 1: Basic custom format with specific parameters first
    console.log('\n1. Testing custom format with known good parameters...');
    
    const params1 = { ivLength: 12, validationOffset: 0 };
    console.log(`Using IV length: ${params1.ivLength}, validation offset: ${params1.validationOffset}`);
    
    const originalText1 = "Hello, custom format test!";
    const textBytes1 = stringToBytes(originalText1);
    
    const encrypted1 = encryptor.encryptCustomGCMFormat(textBytes1, params1.ivLength, params1.validationOffset);
    const decrypted1 = encryptor.decryptCustomGCMFormat(encrypted1, params1.ivLength, params1.validationOffset);
    const decryptedText1 = bytesToString(decrypted1);
    
    console.log('Original:', originalText1);
    console.log('Decrypted:', decryptedText1);
    console.log('Encrypted data length:', encrypted1.length);
    console.log('Expected format: [IV(' + params1.ivLength + ')] + [validation] + [ciphertext+tag]');
    
    check(null, {
        'Custom format encryption/decryption works': () => originalText1 === decryptedText1,
        'Encrypted data has correct structure': () => encrypted1.length === params1.ivLength + 1 + textBytes1.length + 16
    });
    
    // Test 2: Test with different IV lengths
    console.log('\n2. Testing different IV lengths...');
    
    const testIVLengths = [8, 10, 12, 14, 16];
    let ivLengthTests = 0;
    
    for (const testIVLength of testIVLengths) {
        const validationOffset = 0; // Use first byte for simplicity
        const testMessage = `Test message for IV length ${testIVLength}`;
        const testBytes = stringToBytes(testMessage);
        
        try {
            const enc = encryptor.encryptCustomGCMFormat(testBytes, testIVLength, validationOffset);
            const dec = encryptor.decryptCustomGCMFormat(enc, testIVLength, validationOffset);
            const decText = bytesToString(dec);
            
            if (decText === testMessage) {
                ivLengthTests++;
                console.log(`✅ IV length ${testIVLength} works`);
            } else {
                console.error(`❌ IV length ${testIVLength} failed: message mismatch`);
            }
        } catch (error) {
            console.error(`❌ IV length ${testIVLength} failed with error:`, error.message);
        }
    }
    
    console.log(`IV length tests passed: ${ivLengthTests}/${testIVLengths.length}`);
    
    check(null, {
        'All IV length tests passed': () => ivLengthTests === testIVLengths.length,
        'At least 80% of IV length tests passed': () => ivLengthTests >= testIVLengths.length * 0.8
    });
    
    // Test 3: Multiple random parameter combinations
    console.log('\n3. Testing multiple random parameter combinations...');
    
    let successfulTests = 0;
    const totalTests = 5; // Reduced for faster testing
    
    for (let i = 0; i < totalTests; i++) {
        const params = getRandomTestParams();
        const testMessage = `Test message ${i} with params ${params.ivLength}/${params.validationOffset}`;
        const testBytes = stringToBytes(testMessage);
        
        try {
            const enc = encryptor.encryptCustomGCMFormat(testBytes, params.ivLength, params.validationOffset);
            const dec = encryptor.decryptCustomGCMFormat(enc, params.ivLength, params.validationOffset);
            const decText = bytesToString(dec);
            
            if (decText === testMessage) {
                successfulTests++;
                console.log(`✅ Random test ${i}: ${params.ivLength}/${params.validationOffset}`);
            } else {
                console.error(`❌ Test ${i} failed: message mismatch`);
            }
        } catch (error) {
            console.error(`❌ Test ${i} failed with error:`, error.message);
        }
    }
    
    console.log(`Random tests passed: ${successfulTests}/${totalTests}`);
    
    check(null, {
        'All random parameter tests passed': () => successfulTests === totalTests,
        'At least 80% of random tests passed': () => successfulTests >= totalTests * 0.8
    });
    
    // Test 4: Parameter validation
    console.log('\n4. Testing parameter validation...');
    
    const validMessage = stringToBytes("Test message");
    let validationTests = 0;
    
    // Test invalid IV lengths
    try {
        encryptor.encryptCustomGCMFormat(validMessage, 7, 0); // Too small
        console.error('Should have failed with IV length 7');
    } catch (error) {
        validationTests++;
        console.log('✅ Correctly rejected IV length 7');
    }
    
    try {
        encryptor.encryptCustomGCMFormat(validMessage, 17, 0); // Too large
        console.error('Should have failed with IV length 17');
    } catch (error) {
        validationTests++;
        console.log('✅ Correctly rejected IV length 17');
    }
    
    // Test invalid validation offsets
    try {
        encryptor.encryptCustomGCMFormat(validMessage, 12, 12); // Out of range
        console.error('Should have failed with validation offset 12 for IV length 12');
    } catch (error) {
        validationTests++;
        console.log('✅ Correctly rejected validation offset 12 for IV length 12');
    }
    
    try {
        encryptor.encryptCustomGCMFormat(validMessage, 10, -1); // Negative
        console.error('Should have failed with negative validation offset');
    } catch (error) {
        validationTests++;
        console.log('✅ Correctly rejected negative validation offset');
    }
    
    check(null, {
        'All parameter validation tests passed': () => validationTests === 4
    });
    
    // Test 5: Format structure verification
    console.log('\n5. Testing format structure...');
    
    const structureParams = { ivLength: 12, validationOffset: 0 };
    const structureMessage = stringToBytes("Structure test");
    
    const structureEncrypted = encryptor.encryptCustomGCMFormat(structureMessage, structureParams.ivLength, structureParams.validationOffset);
    
    // Verify structure manually
    const iv = structureEncrypted.slice(0, structureParams.ivLength);
    const validationByte = structureEncrypted[structureParams.ivLength];
    const expectedValidationByte = iv[structureParams.validationOffset];
    
    console.log('IV first byte:', iv[0].toString(16).padStart(2, '0'));
    console.log('Validation byte:', validationByte.toString(16).padStart(2, '0'));
    console.log('Structure validation:', validationByte === expectedValidationByte ? '✅ VALID' : '❌ INVALID');
    
    check(null, {
        'Format structure is correct': () => validationByte === expectedValidationByte,
        'IV has correct length': () => iv.length === structureParams.ivLength
    });
    
    // Test 6: Performance test with custom format
    console.log('\n6. Testing custom format performance...');
    
    const perfParams = { ivLength: 12, validationOffset: 0 };
    const iterations = 50;
    const startTime = Date.now();
    let performanceTestPassed = true;
    
    for (let i = 0; i < iterations; i++) {
        const data = stringToBytes(`Performance test ${i}`);
        const enc = encryptor.encryptCustomGCMFormat(data, perfParams.ivLength, perfParams.validationOffset);
        const dec = encryptor.decryptCustomGCMFormat(enc, perfParams.ivLength, perfParams.validationOffset);
        const decStr = bytesToString(dec);
        
        if (decStr !== `Performance test ${i}`) {
            console.error(`Performance test iteration ${i} failed!`);
            performanceTestPassed = false;
            break;
        }
    }
    
    const endTime = Date.now();
    const totalTime = endTime - startTime;
    const avgTime = totalTime / iterations;
    
    console.log(`Completed ${iterations} custom format encrypt/decrypt cycles`);
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Average time per cycle: ${avgTime.toFixed(2)}ms`);
    
    check(null, {
        'Custom format performance test completed': () => performanceTestPassed,
        'Average time per cycle < 15ms': () => avgTime < 15
    });
    
    console.log('\n=== Custom format test completed successfully! ===');
}

// Setup function (runs once)
export function setup() {
    console.log('Setting up k6 encryption extension custom format test...');
    return {};
}

// Teardown function (runs once)
export function teardown(data) {
    console.log('Tearing down k6 encryption extension custom format test...');
}