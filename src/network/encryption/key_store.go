package encryption

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// KeyStoreFile is the name of the file to store keys
const KeyStoreFile = "keys.json"

// KeyInfo represents a cryptographic key pair
type KeyInfo struct {
	ID         string    `json:"id"`         // Unique identifier for the key
	Algorithm  string    `json:"algorithm"`  // Algorithm used (e.g., "kyber768", "dilithium3")
	PublicKey  []byte    `json:"publicKey"`  // Public key data
	PrivateKey []byte    `json:"privateKey"` // Private key data (nil for peer keys)
	PeerID     string    `json:"peerId"`     // Peer ID associated with this key
	CreatedAt  time.Time `json:"createdAt"`  // When the key was created
	IsLocal    bool      `json:"isLocal"`    // Whether this is a local key
}

// KeyStore manages cryptographic keys for the node and peers
type KeyStore struct {
	Keys         map[string]map[string]*KeyInfo `json:"keys"` // PeerID -> Algorithm -> KeyInfo
	keyStorePath string                         // Path to the key store file
	mutex        sync.RWMutex                   // Protects access to the key store
}

// NewKeyStore creates a new key store
func NewKeyStore(configDir string) (*KeyStore, error) {
	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create the key store
	ks := &KeyStore{
		keyStorePath: filepath.Join(configDir, "keystore.json"),
		Keys:         make(map[string]map[string]*KeyInfo),
	}

	// Load existing keys
	if err := ks.Load(); err != nil {
		return nil, fmt.Errorf("failed to load key store: %w", err)
	}

	// Generate default keys if none exist
	if len(ks.Keys) == 0 {
		if err := ks.GenerateDefaultKeys(); err != nil {
			return nil, fmt.Errorf("failed to generate default keys: %w", err)
		}
	}

	return ks, nil
}

// Load loads the key store from disk
func (ks *KeyStore) Load() error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Read the key store file
	data, err := os.ReadFile(ks.keyStorePath)
	if err != nil {
		if os.IsNotExist(err) {
			// If the file doesn't exist, create an empty key store
			ks.Keys = make(map[string]map[string]*KeyInfo)
			return nil
		}
		return fmt.Errorf("failed to read key store file: %w", err)
	}

	// Parse the key store data
	if err := json.Unmarshal(data, &ks.Keys); err != nil {
		return fmt.Errorf("failed to parse key store data: %w", err)
	}

	return nil
}

// Save saves the key store to disk
func (ks *KeyStore) Save() error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Marshal the key store data
	data, err := json.MarshalIndent(ks.Keys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key store data: %w", err)
	}

	// Write the key store file
	if err := os.WriteFile(ks.keyStorePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write key store file: %w", err)
	}

	return nil
}

// GenerateDefaultKeys generates default key pairs for the local peer
func (ks *KeyStore) GenerateDefaultKeys() error {
	// Get the crypto provider
	provider, err := GetCryptoProvider()
	if err != nil {
		return fmt.Errorf("failed to get crypto provider: %w", err)
	}

	// Get local peer ID
	peerID, err := ks.GetMyPeerID()
	if err != nil {
		return fmt.Errorf("failed to get local peer ID: %w", err)
	}

	// Generate Kyber key pair
	kyberKeyPair, err := provider.GenerateKeyPair("kyber768")
	if err != nil {
		return fmt.Errorf("failed to generate Kyber key pair: %w", err)
	}

	// Generate Dilithium key pair
	dilithiumKeyPair, err := provider.GenerateKeyPair("dilithium3")
	if err != nil {
		return fmt.Errorf("failed to generate Dilithium key pair: %w", err)
	}

	// Store the keys
	ks.mutex.Lock()
	if _, exists := ks.Keys[peerID]; !exists {
		ks.Keys[peerID] = make(map[string]*KeyInfo)
	}

	// Store Kyber key
	ks.Keys[peerID]["kyber768"] = &KeyInfo{
		ID:         fmt.Sprintf("%s-kyber768", peerID),
		Algorithm:  "kyber768",
		PublicKey:  kyberKeyPair.PublicKey,
		PrivateKey: kyberKeyPair.PrivateKey,
		PeerID:     peerID,
		CreatedAt:  time.Now(),
		IsLocal:    true,
	}

	// Store Dilithium key
	ks.Keys[peerID]["dilithium3"] = &KeyInfo{
		ID:         fmt.Sprintf("%s-dilithium3", peerID),
		Algorithm:  "dilithium3",
		PublicKey:  dilithiumKeyPair.PublicKey,
		PrivateKey: dilithiumKeyPair.PrivateKey,
		PeerID:     peerID,
		CreatedAt:  time.Now(),
		IsLocal:    true,
	}
	ks.mutex.Unlock()

	// Save to disk
	if err := ks.Save(); err != nil {
		return fmt.Errorf("failed to save default keys: %w", err)
	}

	return nil
}

// GetMyPeerID returns the local peer's ID
func (ks *KeyStore) GetMyPeerID() (string, error) {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Look for any local key to get the peer ID
	for peerID, keys := range ks.Keys {
		for _, key := range keys {
			if key.IsLocal {
				return peerID, nil
			}
		}
	}

	// If no local key found, generate a new peer ID
	_, pubKey, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return "", fmt.Errorf("failed to generate networking key: %w", err)
	}

	// Derive the peer ID from the public key
	peerID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to derive peer ID: %w", err)
	}

	return peerID.String(), nil
}

// GetMyKeyPair returns the local peer's key pair for the specified algorithm
func (ks *KeyStore) GetMyKeyPair(algorithm string) (*KeyInfo, error) {
	// Get local peer ID
	peerID, err := ks.GetMyPeerID()
	if err != nil {
		return nil, fmt.Errorf("failed to get local peer ID: %w", err)
	}

	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Check if we have a key for this algorithm
	if keys, exists := ks.Keys[peerID]; exists {
		if key, exists := keys[algorithm]; exists && key.IsLocal {
			return key, nil
		}
	}

	// If no key found, generate a new one
	ks.mutex.Unlock() // Release lock before generating key
	keyInfo, err := ks.GenerateKey(algorithm)
	ks.mutex.Lock() // Reacquire lock
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	return keyInfo, nil
}

// AddPeerKey adds a peer's public key to the store
func (ks *KeyStore) AddPeerKey(peerID, algorithm string, publicKey []byte) (*KeyInfo, error) {
	// Create the key info
	keyInfo := &KeyInfo{
		ID:         fmt.Sprintf("%s-%s", peerID, algorithm),
		Algorithm:  algorithm,
		PublicKey:  publicKey,
		PrivateKey: nil, // No private key for peer keys
		PeerID:     peerID,
		CreatedAt:  time.Now(),
		IsLocal:    false,
	}

	// Store the key
	ks.mutex.Lock()
	if _, exists := ks.Keys[peerID]; !exists {
		ks.Keys[peerID] = make(map[string]*KeyInfo)
	}
	ks.Keys[peerID][algorithm] = keyInfo
	ks.mutex.Unlock()

	// Save to disk
	if err := ks.Save(); err != nil {
		return nil, fmt.Errorf("failed to save peer key: %w", err)
	}

	return keyInfo, nil
}

// GetPublicKey returns a peer's public key for the specified algorithm
func (ks *KeyStore) GetPublicKey(peerID, algorithm string) ([]byte, error) {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Check if we have a key for this peer and algorithm
	if keys, exists := ks.Keys[peerID]; exists {
		if key, exists := keys[algorithm]; exists {
			return key.PublicKey, nil
		}
	}

	// If no key found and this is our peer ID, generate a new one
	myPeerID, err := ks.GetMyPeerID()
	if err != nil {
		return nil, fmt.Errorf("failed to get local peer ID: %w", err)
	}
	if peerID == myPeerID {
		ks.mutex.Unlock() // Release lock before generating key
		keyInfo, err := ks.GenerateKey(algorithm)
		ks.mutex.Lock() // Reacquire lock
		if err != nil {
			return nil, fmt.Errorf("failed to generate new key: %w", err)
		}
		return keyInfo.PublicKey, nil
	}

	return nil, fmt.Errorf("no public key found for peer %s and algorithm %s", peerID, algorithm)
}

// HasPeerKey checks if we have a public key for a peer and algorithm
func (ks *KeyStore) HasPeerKey(peerID, algorithm string) bool {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	// Check if we have a key for this peer and algorithm
	if keys, exists := ks.Keys[peerID]; exists {
		if key, exists := keys[algorithm]; exists {
			return !key.IsLocal // Only return true for peer keys
		}
	}

	return false
}

// ListPeerIDs returns a list of all peer IDs in the store
func (ks *KeyStore) ListPeerIDs() []string {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	peerIDs := make([]string, 0, len(ks.Keys))
	for peerID := range ks.Keys {
		peerIDs = append(peerIDs, peerID)
	}

	return peerIDs
}

// RemovePeer removes all keys for a peer
func (ks *KeyStore) RemovePeer(peerID string) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Check if peer exists
	if _, exists := ks.Keys[peerID]; !exists {
		return fmt.Errorf("no keys found for peer: %s", peerID)
	}

	// Remove all keys for this peer
	delete(ks.Keys, peerID)

	// Save to disk
	if err := ks.Save(); err != nil {
		return fmt.Errorf("failed to save after removing peer: %w", err)
	}

	return nil
}

// GetKeyInfo returns the key info for a peer and algorithm
func (ks *KeyStore) GetKeyInfo(peerID, algorithm string) (*KeyInfo, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	// Check if we have a key for this peer and algorithm
	if keys, exists := ks.Keys[peerID]; exists {
		if key, exists := keys[algorithm]; exists {
			return key, nil
		}
	}

	return nil, fmt.Errorf("no key found for peer %s and algorithm %s", peerID, algorithm)
}

// AddLocalKey adds a local key to the store
func (ks *KeyStore) AddLocalKey(algorithm string, publicKey, privateKey []byte) (*KeyInfo, error) {
	// Get local peer ID
	peerID, err := ks.GetMyPeerID()
	if err != nil {
		return nil, fmt.Errorf("failed to get local peer ID: %w", err)
	}

	// Create the key info
	keyInfo := &KeyInfo{
		ID:         fmt.Sprintf("%s-%s", peerID, algorithm),
		Algorithm:  algorithm,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		PeerID:     peerID,
		CreatedAt:  time.Now(),
		IsLocal:    true,
	}

	// Store the key
	ks.mutex.Lock()
	if _, exists := ks.Keys[peerID]; !exists {
		ks.Keys[peerID] = make(map[string]*KeyInfo)
	}
	ks.Keys[peerID][algorithm] = keyInfo
	ks.mutex.Unlock()

	// Save to disk
	if err := ks.Save(); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	return keyInfo, nil
}

// ListKeys returns a list of all keys in the store
func (ks *KeyStore) ListKeys() []*KeyInfo {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	// Collect all keys
	keys := make([]*KeyInfo, 0)
	for _, peerKeys := range ks.Keys {
		for _, key := range peerKeys {
			keys = append(keys, key)
		}
	}

	return keys
}

// GenerateKey generates a new key pair for the specified algorithm
func (ks *KeyStore) GenerateKey(algorithm string) (*KeyInfo, error) {
	// Get the crypto provider
	provider, err := GetCryptoProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto provider: %w", err)
	}

	// Generate the key pair
	keyPair, err := provider.GenerateKeyPair(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Get local peer ID
	peerID, err := ks.GetMyPeerID()
	if err != nil {
		return nil, fmt.Errorf("failed to get local peer ID: %w", err)
	}

	// Create the key info
	keyInfo := &KeyInfo{
		ID:         fmt.Sprintf("%s-%s", peerID, algorithm),
		Algorithm:  algorithm,
		PublicKey:  keyPair.PublicKey,
		PrivateKey: keyPair.PrivateKey,
		PeerID:     peerID,
		CreatedAt:  time.Now(),
		IsLocal:    true,
	}

	// Store the key
	ks.mutex.Lock()
	if _, exists := ks.Keys[peerID]; !exists {
		ks.Keys[peerID] = make(map[string]*KeyInfo)
	}
	ks.Keys[peerID][algorithm] = keyInfo
	ks.mutex.Unlock()

	// Save to disk
	if err := ks.Save(); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	return keyInfo, nil
}

// ExportKey exports a key to a JSON format
func (ks *KeyStore) ExportKey(keyID string) ([]byte, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	// Find the key
	var keyInfo *KeyInfo
	for _, peerKeys := range ks.Keys {
		for _, key := range peerKeys {
			if key.PeerID == keyID {
				keyInfo = key
				break
			}
		}
		if keyInfo != nil {
			break
		}
	}

	if keyInfo == nil {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Export the key
	return json.MarshalIndent(keyInfo, "", "  ")
}

// ImportKey imports a key from JSON format
func (ks *KeyStore) ImportKey(keyData []byte) (*KeyInfo, error) {
	var keyInfo KeyInfo
	if err := json.Unmarshal(keyData, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key data: %w", err)
	}

	// Ensure ID is set
	if keyInfo.ID == "" {
		keyInfo.ID = fmt.Sprintf("%s-%s", keyInfo.PeerID, keyInfo.Algorithm)
	}

	// Store the key
	ks.mutex.Lock()
	if _, exists := ks.Keys[keyInfo.PeerID]; !exists {
		ks.Keys[keyInfo.PeerID] = make(map[string]*KeyInfo)
	}
	ks.Keys[keyInfo.PeerID][keyInfo.Algorithm] = &keyInfo
	ks.mutex.Unlock()

	// Save to disk
	if err := ks.Save(); err != nil {
		return nil, fmt.Errorf("failed to save imported key: %w", err)
	}

	return &keyInfo, nil
}

// DeleteKey deletes a key from the store
func (ks *KeyStore) DeleteKey(peerID, algorithm string) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Check if we have a key for this peer and algorithm
	if keys, exists := ks.Keys[peerID]; exists {
		if key, exists := keys[algorithm]; exists {
			// Don't allow deleting local keys
			if key.IsLocal {
				return fmt.Errorf("cannot delete local key")
			}

			// Delete the key
			delete(keys, algorithm)

			// If no more keys for this peer, remove the peer
			if len(keys) == 0 {
				delete(ks.Keys, peerID)
			}

			// Save to disk
			if err := ks.Save(); err != nil {
				return fmt.Errorf("failed to save after deleting key: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("no key found for peer %s and algorithm %s", peerID, algorithm)
}

// RotateKey generates a new key pair and deletes the old one
func (ks *KeyStore) RotateKey(algorithm string) (*KeyInfo, error) {
	// Get the old key
	oldKey, err := ks.GetMyKeyPair(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get old key: %w", err)
	}

	// Generate a new key
	newKey, err := ks.GenerateKey(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	// Delete the old key
	if err := ks.DeleteKey(oldKey.PeerID, oldKey.Algorithm); err != nil {
		return nil, fmt.Errorf("failed to delete old key: %w", err)
	}

	return newKey, nil
}

// BackupKeys exports all keys to JSON format
func (ks *KeyStore) BackupKeys() ([]byte, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	// Marshal the key store data
	data, err := json.MarshalIndent(ks.Keys, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key store data: %w", err)
	}

	return data, nil
}

// RestoreKeys imports all keys from JSON format
func (ks *KeyStore) RestoreKeys(data []byte) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Parse the key store data
	if err := json.Unmarshal(data, &ks.Keys); err != nil {
		return fmt.Errorf("failed to parse key store data: %w", err)
	}

	// Save to disk
	if err := ks.Save(); err != nil {
		return fmt.Errorf("failed to save restored keys: %w", err)
	}

	return nil
}
