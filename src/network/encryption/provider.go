package encryption

import (
	"errors"
	"fmt"
	"sync"
)

// RustCryptoProvider implements the CryptoProvider interface using the Rust crypto library
type RustCryptoProvider struct {
	// Default variants for algorithms
	defaultKyberVariant    KyberVariant
	defaultDilithiumVariant DilithiumVariant
	
	// Cache for key pairs to avoid regeneration
	keyPairCache     map[string]KeyPair
	keyPairCacheMutex sync.RWMutex
}

// NewRustCryptoProvider creates a new provider with the Rust crypto library
func NewRustCryptoProvider() (*RustCryptoProvider, error) {
	provider := &RustCryptoProvider{
		defaultKyberVariant:    Kyber768,     // NIST security level 3
		defaultDilithiumVariant: Dilithium3,   // NIST security level 3
		keyPairCache:           make(map[string]KeyPair),
	}
	
	// Test if the crypto library is available
	_, _, err := kyberKeygen(provider.defaultKyberVariant)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Rust crypto provider: %w", err)
	}
	
	return provider, nil
}

// GenerateKeyPair generates a new key pair for the specified algorithm
func (p *RustCryptoProvider) GenerateKeyPair(algorithm string) (KeyPair, error) {
	var publicKey, privateKey []byte
	var err error
	
	switch algorithm {
	case "kyber512":
		publicKey, privateKey, err = kyberKeygen(Kyber512)
	case "kyber768":
		publicKey, privateKey, err = kyberKeygen(Kyber768)
	case "kyber1024":
		publicKey, privateKey, err = kyberKeygen(Kyber1024)
	case "dilithium2":
		publicKey, privateKey, err = dilithiumKeygen(Dilithium2)
	case "dilithium3":
		publicKey, privateKey, err = dilithiumKeygen(Dilithium3)
	case "dilithium5":
		publicKey, privateKey, err = dilithiumKeygen(Dilithium5)
	default:
		return KeyPair{}, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	
	if err != nil {
		return KeyPair{}, fmt.Errorf("key generation failed: %w", err)
	}
	
	keyPair := KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Algorithm:  algorithm,
	}
	
	// Cache the key pair
	p.keyPairCacheMutex.Lock()
	p.keyPairCache[algorithm] = keyPair
	p.keyPairCacheMutex.Unlock()
	
	return keyPair, nil
}

// Encrypt encrypts plaintext for a recipient's public key
func (p *RustCryptoProvider) Encrypt(plaintext []byte, recipientPublicKey []byte) ([]byte, error) {
	// For encryption, we use Kyber KEM to establish a shared secret,
	// then use that secret as a key for AES-GCM symmetric encryption
	
	// Default to Kyber768
	variant := p.defaultKyberVariant
	
	// Generate a shared secret using Kyber
	ciphertext, sharedSecret, err := kyberEncapsulate(variant, recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("key encapsulation failed: %w", err)
	}
	
	// Use the shared secret to encrypt the message with AES-GCM
	encryptedData, nonce, err := aesGcmEncrypt(sharedSecret, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("symmetric encryption failed: %w", err)
	}
	
	// Format: [ciphertext length (4 bytes)][ciphertext][nonce][encrypted data]
	result := make([]byte, 4+len(ciphertext)+len(nonce)+len(encryptedData))
	
	// Write ciphertext length
	ctLen := uint32(len(ciphertext))
	result[0] = byte(ctLen >> 24)
	result[1] = byte(ctLen >> 16)
	result[2] = byte(ctLen >> 8)
	result[3] = byte(ctLen)
	
	// Write ciphertext
	copy(result[4:], ciphertext)
	
	// Write nonce
	copy(result[4+len(ciphertext):], nonce)
	
	// Write encrypted data
	copy(result[4+len(ciphertext)+len(nonce):], encryptedData)
	
	return result, nil
}

// Decrypt decrypts ciphertext using the local private key
func (p *RustCryptoProvider) Decrypt(ciphertext []byte, privateKey []byte) ([]byte, error) {
	// Check minimum length: 4 bytes for ciphertext length + at least 1 byte for each component
	if len(ciphertext) < 4+1+12+1 { // 4 bytes header + min ciphertext + nonce + min encrypted data
		return nil, errors.New("invalid ciphertext format: too short")
	}
	
	// Extract ciphertext length
	ctLen := uint32(ciphertext[0])<<24 | uint32(ciphertext[1])<<16 | uint32(ciphertext[2])<<8 | uint32(ciphertext[3])
	
	// Validate ciphertext length
	if 4+ctLen > uint32(len(ciphertext)) {
		return nil, errors.New("invalid ciphertext format: incorrect length")
	}
	
	// Extract components
	kyberCiphertext := ciphertext[4 : 4+ctLen]
	nonce := ciphertext[4+ctLen : 4+ctLen+12] // AES-GCM nonce is 12 bytes
	encryptedData := ciphertext[4+ctLen+12:]
	
	// Default to Kyber768
	variant := p.defaultKyberVariant
	
	// Recover the shared secret
	sharedSecret, err := kyberDecapsulate(variant, privateKey, kyberCiphertext)
	if err != nil {
		return nil, fmt.Errorf("key decapsulation failed: %w", err)
	}
	
	// Decrypt the message with AES-GCM
	plaintext, err := aesGcmDecrypt(sharedSecret, encryptedData, nonce, nil)
	if err != nil {
		return nil, fmt.Errorf("symmetric decryption failed: %w", err)
	}
	
	return plaintext, nil
}

// Sign creates a signature for a message using the local private key
func (p *RustCryptoProvider) Sign(message []byte, privateKey []byte) ([]byte, error) {
	// Default to Dilithium3
	variant := p.defaultDilithiumVariant
	
	signature, err := dilithiumSign(variant, privateKey, message)
	if err != nil {
		return nil, fmt.Errorf("signature generation failed: %w", err)
	}
	
	return signature, nil
}

// Verify verifies a signature using the sender's public key
func (p *RustCryptoProvider) Verify(message []byte, signature []byte, publicKey []byte) (bool, error) {
	// Default to Dilithium3
	variant := p.defaultDilithiumVariant
	
	valid, err := dilithiumVerify(variant, publicKey, message, signature)
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %w", err)
	}
	
	return valid, nil
}

// DeriveSharedSecret derives a shared secret from a public key and private key
func (p *RustCryptoProvider) DeriveSharedSecret(publicKey []byte, privateKey []byte) ([]byte, error) {
	// For Kyber, we need to encapsulate using the public key and then decapsulate with the private key
	// However, this is not the normal way to use Kyber. In a real implementation, one side encapsulates
	// and sends the ciphertext, and the other side decapsulates.
	
	// Default to Kyber768
	variant := p.defaultKyberVariant
	
	// Encapsulate (generate a shared secret and ciphertext)
	ciphertext, _, err := kyberEncapsulate(variant, publicKey)
	if err != nil {
		return nil, fmt.Errorf("key encapsulation failed: %w", err)
	}
	
	// Decapsulate (recover the shared secret)
	sharedSecret, err := kyberDecapsulate(variant, privateKey, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("key decapsulation failed: %w", err)
	}
	
	return sharedSecret, nil
} 