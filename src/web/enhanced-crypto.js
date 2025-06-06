// Enhanced QaSa Crypto Module - Quantum-Safe Cryptography

class QaSaCrypto {
    constructor() {
        this.ws = null;
        this.keys = new Map();
        this.peerKeys = new Map();
        this.encryptionStatus = new Map();
        this.quantumOnly = false;
        this.keyRotationInterval = null;
        
        // Initialize Web Crypto API
        this.crypto = window.crypto || window.msCrypto;
        this.subtle = this.crypto.subtle;
    }

    init(ws) {
        this.ws = ws;
        this.loadKeys();
        this.setupKeyRotation();
    }

    // Key Management
    async loadKeys() {
        // Load keys from local storage
        const storedKeys = localStorage.getItem('qasa_keys');
        if (storedKeys) {
            try {
                const keys = JSON.parse(storedKeys);
                for (const [keyId, keyData] of Object.entries(keys)) {
                    this.keys.set(keyId, keyData);
                }
            } catch (error) {
                console.error('Failed to load keys:', error);
            }
        }
    }

    saveKeys() {
        const keysObj = {};
        for (const [keyId, keyData] of this.keys) {
            keysObj[keyId] = keyData;
        }
        localStorage.setItem('qasa_keys', JSON.stringify(keysObj));
    }

    // Generate quantum-safe keys
    async generateKeys(algorithm = 'kyber768') {
        this.sendMessage('generate_keys', { algorithm });
    }

    // Handle keys update from server
    handleKeysUpdate(data) {
        const { keys, operation } = data;
        
        switch (operation) {
            case 'generated':
                keys.forEach(key => {
                    this.keys.set(key.id, key);
                });
                this.saveKeys();
                this.notifyUI('Keys generated successfully', 'success');
                break;
                
            case 'rotated':
                keys.forEach(key => {
                    this.keys.set(key.id, key);
                });
                this.saveKeys();
                this.notifyUI('Keys rotated successfully', 'success');
                break;
                
            case 'imported':
                keys.forEach(key => {
                    this.keys.set(key.id, key);
                });
                this.saveKeys();
                this.notifyUI('Keys imported successfully', 'success');
                break;
                
            case 'peer_keys':
                const { peer_id, peer_keys } = data;
                this.peerKeys.set(peer_id, peer_keys);
                this.updateEncryptionStatus(peer_id);
                break;
        }
    }

    // Key Exchange
    async initiateKeyExchange(peerId) {
        // Get our public keys
        const publicKeys = this.getPublicKeys();
        
        this.sendMessage('key_exchange', {
            peer_id: peerId,
            public_keys: publicKeys,
            algorithms: this.getSupportedAlgorithms()
        });
    }

    getPublicKeys() {
        const publicKeys = {};
        for (const [keyId, keyData] of this.keys) {
            if (keyData.type === 'public' || keyData.public_key) {
                publicKeys[keyId] = {
                    algorithm: keyData.algorithm,
                    key: keyData.public_key || keyData.key,
                    created_at: keyData.created_at
                };
            }
        }
        return publicKeys;
    }

    getSupportedAlgorithms() {
        const algorithms = [];
        
        // Quantum-safe algorithms
        algorithms.push('kyber768', 'dilithium3');
        
        // Classical algorithms (if not quantum-only mode)
        if (!this.quantumOnly) {
            algorithms.push('rsa-4096', 'ed25519', 'x25519');
        }
        
        return algorithms;
    }

    // Encryption/Decryption
    async encryptMessage(message, recipientId) {
        const recipientKeys = this.peerKeys.get(recipientId);
        if (!recipientKeys) {
            throw new Error('No keys available for recipient');
        }
        
        // Select the best available algorithm
        const algorithm = this.selectBestAlgorithm(recipientKeys);
        
        // Generate ephemeral key for this message
        const ephemeralKey = await this.generateEphemeralKey(algorithm);
        
        // Encrypt the message
        const encrypted = await this.performEncryption(message, recipientKeys, ephemeralKey, algorithm);
        
        return {
            algorithm,
            ephemeral_key: ephemeralKey.public,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            tag: encrypted.tag
        };
    }

    async decryptMessage(encryptedData, senderId) {
        const { algorithm, ephemeral_key, ciphertext, nonce, tag } = encryptedData;
        
        // Get our private key for this algorithm
        const privateKey = this.getPrivateKey(algorithm);
        if (!privateKey) {
            throw new Error('No private key available for decryption');
        }
        
        // Perform decryption
        const decrypted = await this.performDecryption(
            ciphertext,
            privateKey,
            ephemeral_key,
            nonce,
            tag,
            algorithm
        );
        
        return decrypted;
    }

    selectBestAlgorithm(recipientKeys) {
        // Priority order for algorithms
        const priority = ['kyber768', 'dilithium3', 'x25519', 'ed25519', 'rsa-4096'];
        
        for (const algo of priority) {
            if (recipientKeys[algo] && this.hasPrivateKey(algo)) {
                return algo;
            }
        }
        
        throw new Error('No compatible encryption algorithm found');
    }

    async generateEphemeralKey(algorithm) {
        switch (algorithm) {
            case 'kyber768':
                return this.generateKyberEphemeralKey();
            case 'x25519':
                return this.generateX25519EphemeralKey();
            default:
                throw new Error(`Unsupported algorithm: ${algorithm}`);
        }
    }

    async performEncryption(message, recipientKeys, ephemeralKey, algorithm) {
        // Convert message to bytes
        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(message);
        
        // Generate shared secret
        const sharedSecret = await this.deriveSharedSecret(
            ephemeralKey.private,
            recipientKeys[algorithm],
            algorithm
        );
        
        // Generate encryption key from shared secret
        const encryptionKey = await this.deriveEncryptionKey(sharedSecret);
        
        // Generate nonce
        const nonce = this.crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt using AES-GCM
        const encrypted = await this.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                tagLength: 128
            },
            encryptionKey,
            messageBytes
        );
        
        // Extract ciphertext and tag
        const ciphertext = new Uint8Array(encrypted, 0, encrypted.byteLength - 16);
        const tag = new Uint8Array(encrypted, encrypted.byteLength - 16);
        
        return {
            ciphertext: this.arrayBufferToBase64(ciphertext),
            nonce: this.arrayBufferToBase64(nonce),
            tag: this.arrayBufferToBase64(tag)
        };
    }

    async performDecryption(ciphertext, privateKey, ephemeralKey, nonce, tag, algorithm) {
        // Decode from base64
        const ciphertextBytes = this.base64ToArrayBuffer(ciphertext);
        const nonceBytes = this.base64ToArrayBuffer(nonce);
        const tagBytes = this.base64ToArrayBuffer(tag);
        
        // Combine ciphertext and tag for AES-GCM
        const combined = new Uint8Array(ciphertextBytes.byteLength + tagBytes.byteLength);
        combined.set(new Uint8Array(ciphertextBytes), 0);
        combined.set(new Uint8Array(tagBytes), ciphertextBytes.byteLength);
        
        // Derive shared secret
        const sharedSecret = await this.deriveSharedSecret(
            privateKey,
            ephemeralKey,
            algorithm
        );
        
        // Generate decryption key
        const decryptionKey = await this.deriveEncryptionKey(sharedSecret);
        
        // Decrypt
        const decrypted = await this.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonceBytes,
                tagLength: 128
            },
            decryptionKey,
            combined
        );
        
        // Convert back to string
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    // Digital Signatures
    async signMessage(message) {
        // Get our signing key (prefer Dilithium for quantum-safety)
        const signingKey = this.getSigningKey();
        if (!signingKey) {
            throw new Error('No signing key available');
        }
        
        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(message);
        
        // Sign the message
        const signature = await this.performSigning(messageBytes, signingKey);
        
        return {
            algorithm: signingKey.algorithm,
            signature: this.arrayBufferToBase64(signature),
            key_id: signingKey.id
        };
    }

    async verifySignature(message, signatureData, senderId) {
        const { algorithm, signature, key_id } = signatureData;
        
        // Get sender's public key
        const senderKeys = this.peerKeys.get(senderId);
        if (!senderKeys || !senderKeys[algorithm]) {
            return false;
        }
        
        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(message);
        const signatureBytes = this.base64ToArrayBuffer(signature);
        
        return await this.performVerification(
            messageBytes,
            signatureBytes,
            senderKeys[algorithm],
            algorithm
        );
    }

    getSigningKey() {
        // Prefer quantum-safe signing (Dilithium)
        for (const [keyId, keyData] of this.keys) {
            if (keyData.algorithm === 'dilithium3' && keyData.private_key) {
                return keyData;
            }
        }
        
        // Fallback to classical signing if not quantum-only
        if (!this.quantumOnly) {
            for (const [keyId, keyData] of this.keys) {
                if ((keyData.algorithm === 'ed25519' || keyData.algorithm === 'rsa-4096') && keyData.private_key) {
                    return keyData;
                }
            }
        }
        
        return null;
    }

    async performSigning(messageBytes, signingKey) {
        switch (signingKey.algorithm) {
            case 'dilithium3':
                return this.signWithDilithium(messageBytes, signingKey);
            case 'ed25519':
                return this.signWithEd25519(messageBytes, signingKey);
            case 'rsa-4096':
                return this.signWithRSA(messageBytes, signingKey);
            default:
                throw new Error(`Unsupported signing algorithm: ${signingKey.algorithm}`);
        }
    }

    async performVerification(messageBytes, signatureBytes, publicKey, algorithm) {
        switch (algorithm) {
            case 'dilithium3':
                return this.verifyWithDilithium(messageBytes, signatureBytes, publicKey);
            case 'ed25519':
                return this.verifyWithEd25519(messageBytes, signatureBytes, publicKey);
            case 'rsa-4096':
                return this.verifyWithRSA(messageBytes, signatureBytes, publicKey);
            default:
                return false;
        }
    }

    // File Encryption
    async encryptFile(file) {
        // Read file as array buffer
        const fileBuffer = await this.readFileAsArrayBuffer(file);
        
        // Generate file encryption key
        const fileKey = await this.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );
        
        // Generate IV
        const iv = this.crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt file
        const encrypted = await this.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            fileKey,
            fileBuffer
        );
        
        // Export file key
        const exportedKey = await this.subtle.exportKey('raw', fileKey);
        
        // Create encrypted file blob with metadata
        const metadata = {
            filename: file.name,
            size: file.size,
            type: file.type,
            iv: this.arrayBufferToBase64(iv),
            key: this.arrayBufferToBase64(exportedKey)
        };
        
        const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
        const metadataLength = new Uint32Array([metadataBytes.length]);
        
        // Combine metadata length, metadata, and encrypted data
        const combined = new Uint8Array(
            4 + metadataBytes.length + encrypted.byteLength
        );
        combined.set(new Uint8Array(metadataLength.buffer), 0);
        combined.set(metadataBytes, 4);
        combined.set(new Uint8Array(encrypted), 4 + metadataBytes.length);
        
        return new File([combined], file.name + '.encrypted', { type: 'application/octet-stream' });
    }

    async decryptFile(encryptedFile) {
        // Read encrypted file
        const fileBuffer = await this.readFileAsArrayBuffer(encryptedFile);
        const dataView = new DataView(fileBuffer);
        
        // Extract metadata length
        const metadataLength = dataView.getUint32(0, true);
        
        // Extract metadata
        const metadataBytes = new Uint8Array(fileBuffer, 4, metadataLength);
        const metadata = JSON.parse(new TextDecoder().decode(metadataBytes));
        
        // Extract encrypted data
        const encryptedData = new Uint8Array(fileBuffer, 4 + metadataLength);
        
        // Import file key
        const keyBytes = this.base64ToArrayBuffer(metadata.key);
        const fileKey = await this.subtle.importKey(
            'raw',
            keyBytes,
            'AES-GCM',
            false,
            ['decrypt']
        );
        
        // Decrypt file
        const iv = this.base64ToArrayBuffer(metadata.iv);
        const decrypted = await this.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            fileKey,
            encryptedData
        );
        
        // Create decrypted file
        return new File([decrypted], metadata.filename, { type: metadata.type });
    }

    readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    // Key Derivation
    async deriveSharedSecret(privateKey, publicKey, algorithm) {
        // This would normally call the backend for quantum-safe operations
        // For now, we'll use a placeholder that calls the backend
        const response = await this.sendMessageAndWait('derive_shared_secret', {
            private_key: privateKey,
            public_key: publicKey,
            algorithm: algorithm
        });
        
        return this.base64ToArrayBuffer(response.shared_secret);
    }

    async deriveEncryptionKey(sharedSecret) {
        // Use HKDF to derive encryption key
        const salt = new Uint8Array(32); // Could use a proper salt
        const info = new TextEncoder().encode('qasa-encryption-key');
        
        const keyMaterial = await this.subtle.importKey(
            'raw',
            sharedSecret,
            'HKDF',
            false,
            ['deriveKey']
        );
        
        return await this.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt,
                info: info
            },
            keyMaterial,
            {
                name: 'AES-GCM',
                length: 256
            },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // Backend Communication for Quantum Operations
    async sendMessageAndWait(type, data) {
        return new Promise((resolve, reject) => {
            const messageId = this.generateMessageId();
            const timeout = setTimeout(() => {
                delete this.pendingRequests[messageId];
                reject(new Error('Request timeout'));
            }, 30000);
            
            this.pendingRequests = this.pendingRequests || {};
            this.pendingRequests[messageId] = { resolve, reject, timeout };
            
            this.sendMessage(type, { ...data, message_id: messageId });
        });
    }

    handleBackendResponse(data) {
        const { message_id, result, error } = data;
        const pending = this.pendingRequests[message_id];
        
        if (pending) {
            clearTimeout(pending.timeout);
            delete this.pendingRequests[message_id];
            
            if (error) {
                pending.reject(new Error(error));
            } else {
                pending.resolve(result);
            }
        }
    }

    // Quantum-Safe Implementations (Backend Calls)
    async generateKyberEphemeralKey() {
        const response = await this.sendMessageAndWait('generate_ephemeral_key', {
            algorithm: 'kyber768'
        });
        
        return {
            private: response.private_key,
            public: response.public_key
        };
    }

    async signWithDilithium(messageBytes, signingKey) {
        const response = await this.sendMessageAndWait('sign_message', {
            message: this.arrayBufferToBase64(messageBytes),
            key_id: signingKey.id,
            algorithm: 'dilithium3'
        });
        
        return this.base64ToArrayBuffer(response.signature);
    }

    async verifyWithDilithium(messageBytes, signatureBytes, publicKey) {
        const response = await this.sendMessageAndWait('verify_signature', {
            message: this.arrayBufferToBase64(messageBytes),
            signature: this.arrayBufferToBase64(signatureBytes),
            public_key: publicKey,
            algorithm: 'dilithium3'
        });
        
        return response.valid;
    }

    // Classical Crypto Implementations
    async generateX25519EphemeralKey() {
        const keyPair = await this.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: 'P-256' // WebCrypto doesn't support X25519 directly
            },
            true,
            ['deriveKey']
        );
        
        const publicKey = await this.subtle.exportKey('raw', keyPair.publicKey);
        
        return {
            private: keyPair.privateKey,
            public: this.arrayBufferToBase64(publicKey)
        };
    }

    async signWithEd25519(messageBytes, signingKey) {
        // Ed25519 not directly supported in WebCrypto, use backend
        const response = await this.sendMessageAndWait('sign_message', {
            message: this.arrayBufferToBase64(messageBytes),
            key_id: signingKey.id,
            algorithm: 'ed25519'
        });
        
        return this.base64ToArrayBuffer(response.signature);
    }

    async verifyWithEd25519(messageBytes, signatureBytes, publicKey) {
        const response = await this.sendMessageAndWait('verify_signature', {
            message: this.arrayBufferToBase64(messageBytes),
            signature: this.arrayBufferToBase64(signatureBytes),
            public_key: publicKey,
            algorithm: 'ed25519'
        });
        
        return response.valid;
    }

    async signWithRSA(messageBytes, signingKey) {
        // Import RSA key
        const privateKey = await this.subtle.importKey(
            'pkcs8',
            this.base64ToArrayBuffer(signingKey.private_key),
            {
                name: 'RSA-PSS',
                hash: 'SHA-256'
            },
            false,
            ['sign']
        );
        
        return await this.subtle.sign(
            {
                name: 'RSA-PSS',
                saltLength: 32
            },
            privateKey,
            messageBytes
        );
    }

    async verifyWithRSA(messageBytes, signatureBytes, publicKey) {
        // Import RSA public key
        const pubKey = await this.subtle.importKey(
            'spki',
            this.base64ToArrayBuffer(publicKey),
            {
                name: 'RSA-PSS',
                hash: 'SHA-256'
            },
            false,
            ['verify']
        );
        
        return await this.subtle.verify(
            {
                name: 'RSA-PSS',
                saltLength: 32
            },
            pubKey,
            signatureBytes,
            messageBytes
        );
    }

    // Encryption Status
    checkEncryptionStatus(peerId) {
        const peerKeys = this.peerKeys.get(peerId);
        const hasQuantumKeys = peerKeys && (peerKeys.kyber768 || peerKeys.dilithium3);
        const hasClassicalKeys = peerKeys && (peerKeys.x25519 || peerKeys.ed25519 || peerKeys['rsa-4096']);
        
        const status = {
            available: !!(peerKeys && (hasQuantumKeys || (!this.quantumOnly && hasClassicalKeys))),
            quantum_safe: hasQuantumKeys,
            algorithms: peerKeys ? Object.keys(peerKeys) : []
        };
        
        this.encryptionStatus.set(peerId, status);
        return status;
    }

    handleEncryptionStatus(data) {
        const { peer_id, status } = data;
        this.encryptionStatus.set(peer_id, status);
        
        // Notify UI
        window.qasaApp?.uiModule?.updateEncryptionStatus(peer_id, status);
    }

    hasKeysFor(peerId) {
        const status = this.encryptionStatus.get(peerId);
        return status && status.available;
    }

    hasPrivateKey(algorithm) {
        for (const [keyId, keyData] of this.keys) {
            if (keyData.algorithm === algorithm && keyData.private_key) {
                return true;
            }
        }
        return false;
    }

    getPrivateKey(algorithm) {
        for (const [keyId, keyData] of this.keys) {
            if (keyData.algorithm === algorithm && keyData.private_key) {
                return keyData.private_key;
            }
        }
        return null;
    }

    // Key Rotation
    setupKeyRotation() {
        const rotationInterval = this.getKeyRotationInterval();
        if (rotationInterval > 0) {
            this.keyRotationInterval = setInterval(() => {
                this.rotateKeys();
            }, rotationInterval);
        }
    }

    getKeyRotationInterval() {
        const settings = window.qasaApp?.settings || {};
        switch (settings.keyRotation) {
            case 'daily':
                return 24 * 60 * 60 * 1000;
            case 'weekly':
                return 7 * 24 * 60 * 60 * 1000;
            case 'monthly':
                return 30 * 24 * 60 * 60 * 1000;
            default:
                return 0; // Manual rotation
        }
    }

    async rotateKeys() {
        this.sendMessage('rotate_keys', {
            algorithms: this.getSupportedAlgorithms()
        });
    }

    // Settings
    setQuantumOnly(enabled) {
        this.quantumOnly = enabled;
        // Re-check encryption status for all peers
        for (const peerId of this.peerKeys.keys()) {
            this.checkEncryptionStatus(peerId);
        }
    }

    // Utility Functions
    sendMessage(type, data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: `crypto_${type}`,
                data
            }));
        }
    }

    generateMessageId() {
        return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    notifyUI(message, type) {
        if (window.qasaApp) {
            window.qasaApp.uiModule.showNotification(message, type);
        }
    }

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Export/Import Keys
    async exportKeys() {
        const exportData = {
            version: '1.0',
            timestamp: new Date().toISOString(),
            keys: []
        };
        
        for (const [keyId, keyData] of this.keys) {
            // Only export private keys that belong to us
            if (keyData.private_key) {
                exportData.keys.push({
                    id: keyId,
                    algorithm: keyData.algorithm,
                    created_at: keyData.created_at,
                    private_key: keyData.private_key,
                    public_key: keyData.public_key
                });
            }
        }
        
        // Encrypt the export with a password
        const password = prompt('Enter a password to encrypt your keys:');
        if (!password) return null;
        
        const encrypted = await this.encryptWithPassword(JSON.stringify(exportData), password);
        
        return {
            encrypted: true,
            data: encrypted
        };
    }

    async importKeys(encryptedData, password) {
        try {
            const decrypted = await this.decryptWithPassword(encryptedData, password);
            const exportData = JSON.parse(decrypted);
            
            if (exportData.version !== '1.0') {
                throw new Error('Unsupported key export version');
            }
            
            // Import keys
            exportData.keys.forEach(keyData => {
                this.keys.set(keyData.id, keyData);
            });
            
            this.saveKeys();
            this.notifyUI('Keys imported successfully', 'success');
            
            // Notify backend about imported keys
            this.sendMessage('keys_imported', {
                keys: exportData.keys.map(k => ({
                    id: k.id,
                    algorithm: k.algorithm,
                    public_key: k.public_key
                }))
            });
            
            return true;
        } catch (error) {
            console.error('Failed to import keys:', error);
            this.notifyUI('Failed to import keys: ' + error.message, 'error');
            return false;
        }
    }

    async encryptWithPassword(data, password) {
        const encoder = new TextEncoder();
        const dataBytes = encoder.encode(data);
        
        // Derive key from password
        const passwordKey = await this.derivePasswordKey(password);
        
        // Generate salt and IV
        const salt = this.crypto.getRandomValues(new Uint8Array(32));
        const iv = this.crypto.getRandomValues(new Uint8Array(12));
        
        // Derive encryption key
        const encryptionKey = await this.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            passwordKey,
            {
                name: 'AES-GCM',
                length: 256
            },
            false,
            ['encrypt']
        );
        
        // Encrypt
        const encrypted = await this.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            encryptionKey,
            dataBytes
        );
        
        // Combine salt, IV, and encrypted data
        const combined = new Uint8Array(32 + 12 + encrypted.byteLength);
        combined.set(salt, 0);
        combined.set(iv, 32);
        combined.set(new Uint8Array(encrypted), 44);
        
        return this.arrayBufferToBase64(combined);
    }

    async decryptWithPassword(encryptedData, password) {
        const combined = this.base64ToArrayBuffer(encryptedData);
        const combinedArray = new Uint8Array(combined);
        
        // Extract salt, IV, and encrypted data
        const salt = combinedArray.slice(0, 32);
        const iv = combinedArray.slice(32, 44);
        const encrypted = combinedArray.slice(44);
        
        // Derive key from password
        const passwordKey = await this.derivePasswordKey(password);
        
        // Derive decryption key
        const decryptionKey = await this.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            passwordKey,
            {
                name: 'AES-GCM',
                length: 256
            },
            false,
            ['decrypt']
        );
        
        // Decrypt
        const decrypted = await this.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            decryptionKey,
            encrypted
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    async derivePasswordKey(password) {
        const encoder = new TextEncoder();
        const passwordBytes = encoder.encode(password);
        
        return await this.subtle.importKey(
            'raw',
            passwordBytes,
            'PBKDF2',
            false,
            ['deriveKey']
        );
    }
}