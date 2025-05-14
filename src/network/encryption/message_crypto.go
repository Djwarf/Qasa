package encryption

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// MessageCrypto provides message encryption/decryption workflow
type MessageCrypto struct {
	provider        CryptoProvider
	keyStore        *KeyStore
	sessionManager  *SessionManager
	rotationManager *KeyRotationManager
	rotationMutex   sync.Mutex
	configDir       string
}

// NewMessageCrypto creates a new message encryption/decryption workflow manager
func NewMessageCrypto(provider CryptoProvider, keyStorePath string) (*MessageCrypto, error) {
	keyStore, err := NewKeyStore(keyStorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key store: %w", err)
	}

	// Create the new rotation manager with default policy
	rotationManager := NewKeyRotationManager(keyStore, provider, DefaultRotationPolicy())

	return &MessageCrypto{
		provider:        provider,
		keyStore:        keyStore,
		sessionManager:  NewSessionManager(),
		rotationManager: rotationManager,
		configDir:       keyStorePath,
	}, nil
}

// SetKeyLifetime sets the lifetime for session keys
func (mc *MessageCrypto) SetKeyLifetime(duration time.Duration) {
	mc.sessionManager.SetKeyLifetime(duration)
}

// SetRotationInterval sets the interval for key rotation
func (mc *MessageCrypto) SetRotationInterval(duration time.Duration) {
	mc.sessionManager.SetRotationInterval(duration)
}

// EncryptMessage encrypts a message for a recipient
func (mc *MessageCrypto) EncryptMessage(plaintext []byte, recipientID string) ([]byte, error) {
	// Get recipient's public key from key store
	recipientKey, err := mc.keyStore.GetPublicKey(recipientID, "kyber768")
	if err != nil {
		return nil, fmt.Errorf("failed to get recipient public key: %w", err)
	}

	// Check if we should rotate the session key
	if mc.sessionManager.ShouldRotateKey(recipientID) {
		mc.rotationMutex.Lock()
		defer mc.rotationMutex.Unlock()

		// Double-check after acquiring the lock
		if mc.sessionManager.ShouldRotateKey(recipientID) {
			// Create a key generator function
			keyGenerator := func() ([]byte, error) {
				return mc.EstablishSessionKey(recipientID)
			}

			// Rotate the key
			_, err := mc.sessionManager.RotateSessionKey(recipientID, keyGenerator)
			if err != nil {
				log.Printf("Warning: Failed to rotate session key: %s\n", err)
				// Continue with existing key or direct encryption
			}
		}
	}

	// Check if we have a valid session key for this recipient
	sessionKey, keyID, found := mc.sessionManager.GetCurrentSessionKey(recipientID)
	if found {
		// Use existing session key for encryption
		return mc.encryptWithSessionKey(plaintext, sessionKey.Key, keyID)
	}

	// No valid session key, use direct encryption
	ciphertext, err := mc.provider.Encrypt(plaintext, recipientKey)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Create a format indicator for direct encryption
	// Format: [0x01][ciphertext]
	result := make([]byte, 1+len(ciphertext))
	result[0] = 0x01 // Direct encryption marker
	copy(result[1:], ciphertext)

	return result, nil
}

// encryptWithSessionKey encrypts a message using a session key
func (mc *MessageCrypto) encryptWithSessionKey(plaintext []byte, sessionKey []byte, keyID uint64) ([]byte, error) {
	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext using AES-GCM with the session key
	encryptedData, _, err := aesGcmEncrypt(sessionKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("session key encryption failed: %w", err)
	}

	// Format: [0x02][session key ID (8 bytes)][nonce][encrypted data]
	result := make([]byte, 1+8+len(nonce)+len(encryptedData))

	result[0] = 0x02 // Session key encryption marker
	binary.BigEndian.PutUint64(result[1:9], keyID)
	copy(result[9:], nonce)
	copy(result[9+len(nonce):], encryptedData)

	return result, nil
}

// DecryptMessage decrypts a message
func (mc *MessageCrypto) DecryptMessage(ciphertext []byte, senderID string) ([]byte, error) {
	if len(ciphertext) < 1 {
		return nil, errors.New("invalid ciphertext: too short")
	}

	// Get my private key from key store
	myKey, err := mc.keyStore.GetMyKeyPair("kyber768")
	if err != nil {
		return nil, fmt.Errorf("failed to get my key pair: %w", err)
	}

	// Check encryption type marker
	encType := ciphertext[0]
	switch encType {
	case 0x01: // Direct encryption
		return mc.provider.Decrypt(ciphertext[1:], myKey.PrivateKey)

	case 0x02: // Session key encryption
		if len(ciphertext) < 9+12 { // Marker + Key ID + Minimum nonce size
			return nil, errors.New("invalid session-encrypted ciphertext: too short")
		}

		// Extract session key ID
		sessionKeyID := binary.BigEndian.Uint64(ciphertext[1:9])

		// Get the session key
		sessionKey, found := mc.sessionManager.GetSessionKeyByID(sessionKeyID)
		if !found {
			return nil, fmt.Errorf("session key not found: %d", sessionKeyID)
		}

		// Extract nonce and encrypted data
		nonce := ciphertext[9:21]
		encryptedData := ciphertext[21:]

		// Decrypt the message
		return aesGcmDecrypt(sessionKey.Key, encryptedData, nonce, nil)

	default:
		return nil, fmt.Errorf("unknown encryption type: %d", encType)
	}
}

// EstablishSessionKey establishes a new session key with a peer
func (mc *MessageCrypto) EstablishSessionKey(peerID string) ([]byte, error) {
	// Get peer's public key
	peerKey, err := mc.keyStore.GetPublicKey(peerID, "kyber768")
	if err != nil {
		return nil, fmt.Errorf("failed to get peer public key: %w", err)
	}

	// Get my key pair
	myKey, err := mc.keyStore.GetMyKeyPair("kyber768")
	if err != nil {
		return nil, fmt.Errorf("failed to get my key pair: %w", err)
	}

	// Derive a shared secret
	sharedSecret, err := mc.provider.DeriveSharedSecret(peerKey, myKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Store the session key
	mc.sessionManager.StoreSessionKey(peerID, sharedSecret)

	return sharedSecret, nil
}

// StartKeyRotation starts background routines for key rotation
func (mc *MessageCrypto) StartKeyRotation(ctx context.Context) {
	// Create a context that can be cancelled
	rotationCtx, cancel := context.WithCancel(ctx)

	// Start session key rotation - short-term keys
	// Run the cleanup every minute
	sessionTicker := time.NewTicker(1 * time.Minute)

	go func() {
		for {
			select {
			case <-sessionTicker.C:
				// Clean up expired session keys
				mc.sessionManager.CleanupExpiredKeys()
			case <-rotationCtx.Done():
				sessionTicker.Stop()
				return
			}
		}
	}()

	// Start long-term key rotation (Kyber and Dilithium keys)
	mc.rotationManager.StartKeyRotation(rotationCtx)

	// If context is done, cancel our derived context
	go func() {
		<-ctx.Done()
		cancel()
	}()
}

// SetRotationPolicy sets the key rotation policy
func (mc *MessageCrypto) SetRotationPolicy(policy *RotationPolicy) {
	mc.rotationManager = NewKeyRotationManager(mc.keyStore, mc.provider, policy)
}

// ApplyHighSecurityPolicy applies high security settings for key rotation
func (mc *MessageCrypto) ApplyHighSecurityPolicy() {
	mc.SetRotationPolicy(HighSecurityRotationPolicy())
	mc.sessionManager.SetKeyLifetime(4 * time.Hour)      // Shorter session key lifetime
	mc.sessionManager.SetRotationInterval(1 * time.Hour) // More frequent rotation
}

// VerifyKeyIntegrity checks if the keys are valid and not corrupted
func (mc *MessageCrypto) VerifyKeyIntegrity() error {
	// Get my peer ID
	peerID, err := mc.keyStore.GetMyPeerID()
	if err != nil {
		return err
	}

	// Check Kyber key
	kyberKeyInfo, err := mc.keyStore.GetKeyInfo(peerID, "kyber768")
	if err != nil {
		return fmt.Errorf("failed to get Kyber key: %w", err)
	}

	// Check Dilithium key
	dilithiumKeyInfo, err := mc.keyStore.GetKeyInfo(peerID, "dilithium3")
	if err != nil {
		return fmt.Errorf("failed to get Dilithium key: %w", err)
	}

	// Verify that the keys have both public and private components
	if len(kyberKeyInfo.PublicKey) == 0 || len(kyberKeyInfo.PrivateKey) == 0 {
		return fmt.Errorf("invalid Kyber key: missing key components")
	}

	if len(dilithiumKeyInfo.PublicKey) == 0 || len(dilithiumKeyInfo.PrivateKey) == 0 {
		return fmt.Errorf("invalid Dilithium key: missing key components")
	}

	return nil
}

// SignMessage signs a message using the local identity
func (mc *MessageCrypto) SignMessage(message []byte) ([]byte, error) {
	// Get my signing key
	myKey, err := mc.keyStore.GetMyKeyPair("dilithium3")
	if err != nil {
		return nil, fmt.Errorf("failed to get my signing key: %w", err)
	}

	// Sign the message
	signature, err := mc.provider.Sign(message, myKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signature, nil
}

// VerifySignature verifies a message signature
func (mc *MessageCrypto) VerifySignature(message, signature []byte, senderID string) (bool, error) {
	// Get sender's public key
	senderKey, err := mc.keyStore.GetPublicKey(senderID, "dilithium3")
	if err != nil {
		return false, fmt.Errorf("failed to get sender public key: %w", err)
	}

	// Verify the signature
	return mc.provider.Verify(message, signature, senderKey)
}

// GetMyPeerID returns the peer ID of the local node
func (mc *MessageCrypto) GetMyPeerID() (string, error) {
	return mc.keyStore.GetMyPeerID()
}

// GetMyPublicKey retrieves a public key for the local node
func (mc *MessageCrypto) GetMyPublicKey(peerID, algorithm string) ([]byte, error) {
	return mc.keyStore.GetPublicKey(peerID, algorithm)
}
