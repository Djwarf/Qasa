package encryption

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// RotationPolicy defines how and when keys should be rotated
type RotationPolicy struct {
	// How often keys should be rotated
	RotationInterval time.Duration

	// How many old keys to keep after rotation
	OldKeysToKeep int

	// Whether to automatically rotate keys that are due
	AutoRotate bool
}

// DefaultRotationPolicy returns a standard security policy (90 days)
func DefaultRotationPolicy() *RotationPolicy {
	return &RotationPolicy{
		RotationInterval: 90 * 24 * time.Hour, // 90 days
		OldKeysToKeep:    2,
		AutoRotate:       true,
	}
}

// HighSecurityRotationPolicy returns a policy for high security environments
func HighSecurityRotationPolicy() *RotationPolicy {
	return &RotationPolicy{
		RotationInterval: 30 * 24 * time.Hour, // 30 days
		OldKeysToKeep:    3,
		AutoRotate:       true,
	}
}

// KeyRotationManager handles long-term key rotation
type KeyRotationManager struct {
	keyStore      *KeyStore
	provider      CryptoProvider
	policy        *RotationPolicy
	mutex         sync.Mutex
	lastRotations map[string]time.Time
}

// NewKeyRotationManager creates a new key rotation manager
func NewKeyRotationManager(keyStore *KeyStore, provider CryptoProvider, policy *RotationPolicy) *KeyRotationManager {
	if policy == nil {
		policy = DefaultRotationPolicy()
	}

	return &KeyRotationManager{
		keyStore:      keyStore,
		provider:      provider,
		policy:        policy,
		lastRotations: make(map[string]time.Time),
	}
}

// IsKeyRotationDue checks if a key is due for rotation
func (krm *KeyRotationManager) IsKeyRotationDue(algorithm string) (bool, error) {
	// Get the key info
	peerID, err := krm.keyStore.GetMyPeerID()
	if err != nil {
		return false, err
	}

	krm.mutex.Lock()
	defer krm.mutex.Unlock()

	// Check last rotation time
	lastRotation, exists := krm.lastRotations[algorithm]
	if !exists {
		// If we've never recorded a rotation, check creation time from key store
		keyInfo, err := krm.keyStore.GetKeyInfo(peerID, algorithm)
		if err != nil {
			return false, err
		}

		lastRotation = keyInfo.CreatedAt
		krm.lastRotations[algorithm] = lastRotation
	}

	// Check if rotation is due
	return time.Since(lastRotation) > krm.policy.RotationInterval, nil
}

// RotateKey rotates a key for the specified algorithm
func (krm *KeyRotationManager) RotateKey(algorithm string) error {
	krm.mutex.Lock()
	defer krm.mutex.Unlock()

	log.Printf("Rotating key for algorithm: %s", algorithm)

	// Generate a new key pair
	newKey, err := krm.provider.GenerateKeyPair(algorithm)
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	// Get my peer ID
	peerID, err := krm.keyStore.GetMyPeerID()
	if err != nil {
		return err
	}

	// Store the new key
	now := time.Now()
	if err := krm.keyStore.AddLocalKey(peerID, algorithm, newKey.PublicKey, newKey.PrivateKey); err != nil {
		return fmt.Errorf("failed to store new key: %w", err)
	}

	// Update last rotation time
	krm.lastRotations[algorithm] = now

	log.Printf("Successfully rotated key for algorithm %s", algorithm)
	return nil
}

// CheckAndRotateKeys checks all keys and rotates those that are due
func (krm *KeyRotationManager) CheckAndRotateKeys() error {
	// Check all key algorithms that we support
	algorithms := []string{"kyber768", "dilithium3"}

	for _, algorithm := range algorithms {
		due, err := krm.IsKeyRotationDue(algorithm)
		if err != nil {
			log.Printf("Error checking rotation for %s: %v", algorithm, err)
			continue
		}

		if due && krm.policy.AutoRotate {
			if err := krm.RotateKey(algorithm); err != nil {
				log.Printf("Error rotating key for %s: %v", algorithm, err)
			}
		}
	}

	return nil
}

// StartKeyRotation starts automatic key rotation
func (krm *KeyRotationManager) StartKeyRotation(ctx context.Context) {
	// Check for key rotation once per day
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Do an initial check
	go krm.CheckAndRotateKeys()

	// Check periodically
	go func() {
		for {
			select {
			case <-ticker.C:
				krm.CheckAndRotateKeys()
			case <-ctx.Done():
				return
			}
		}
	}()
}
