import encryption from 'k6/x/encryption';

export default function () {
    console.log('=== Simple k6 Encryption Test ===');
    
    // Debug: Check what's available on the encryption object
    console.log('Encryption object:', typeof encryption);
    console.log('Encryption object keys:', Object.keys(encryption || {}));
    
    // Try to check if the methods exist
    if (encryption) {
        console.log('generateQualifiedKey exists:', typeof encryption.generateQualifiedKey);
        console.log('newEncryptor exists:', typeof encryption.newEncryptor);
        
        try {
            // Test key generation
            console.log('Attempting to generate key...');
            const key = encryption.generateQualifiedKey();
            console.log('Generated key:', key);
            console.log('Key length:', key ? key.length : 'undefined');
            
            // Test encryptor creation
            if (key) {
                console.log('Attempting to create encryptor...');
                const encryptor = encryption.newEncryptor(key);
                console.log('Encryptor created:', typeof encryptor);
                
                if (encryptor) {
                    console.log('Encryptor methods:', Object.keys(encryptor || {}));
                    
                    // Test simple encryption
                    const testText = "Hello World";
                    console.log('Testing encryption of:', testText);
                    
                    if (typeof encryptor.encryptString === 'function') {
                        const encrypted = encryptor.encryptString(testText);
                        console.log('Encrypted:', encrypted);
                        
                        if (typeof encryptor.decryptString === 'function') {
                            const decrypted = encryptor.decryptString(encrypted);
                            console.log('Decrypted:', decrypted);
                            console.log('Match:', testText === decrypted);
                        } else {
                            console.log('decryptString method not found');
                        }
                    } else {
                        console.log('encryptString method not found');
                    }
                }
            }
        } catch (error) {
            console.error('Error during test:', error.message);
            console.error('Error stack:', error.stack);
        }
    } else {
        console.error('Encryption module not loaded properly');
    }
    
    console.log('=== Test completed ===');
}