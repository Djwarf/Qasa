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

// KeyInfo represents information about a stored key
type KeyInfo struct {
	ID         string    `json:"id"` // Unique identifier for the key
	Algorithm  string    `json:"algorithm"`
	PublicKey  []byte    `json:"public_key"`
	PrivateKey []byte    `json:"private_key,omitempty"` // Only stored for local keys
	PeerID     string    `json:"peer_id"`
	CreatedAt  time.Time `json:"created_at"`
	IsLocal    bool      `json:"is_local"`
}

// KeyStore manages cryptographic keys for the node and peers
type KeyStore struct {
	Keys       map[string]map[string]*KeyInfo `json:"keys"` // PeerID -> Algorithm -> KeyInfo
	configDir  string
	configPath string
	mutex      sync.RWMutex
}

// NewKeyStore creates a new key store
func NewKeyStore(configDir string) (*KeyStore, error) {
	ks := &KeyStore{
		Keys:      make(map[string]map[string]*KeyInfo),
		configDir: configDir,
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	ks.configPath = filepath.Join(configDir, KeyStoreFile)

	// Try to load existing keys
	if err := ks.Load(); err != nil {
		// If file doesn't exist, initialize with defaults
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load key store: %w", err)
		}

		// Generate and save default keys
		if err := ks.GenerateDefaultKeys(); err != nil {
			return nil, fmt.Errorf("failed to generate default keys: %w", err)
		}
	}

	return ks, nil
}

// Load loads keys from the configuration file
func (ks *KeyStore) Load() error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	data, err := os.ReadFile(ks.configPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, ks)
}

// Save saves the keys to the configuration file
func (ks *KeyStore) Save() error {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key store: %w", err)
	}

	return os.WriteFile(ks.configPath, data, 0600) // More restrictive permissions for keys
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

// GetKeyInfo retrieves the full key info for a peer and algorithm
func (ks *KeyStore) GetKeyInfo(peerID, algorithm string) (*KeyInfo, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	// Check if peer exists
	keys, exists := ks.Keys[peerID]
	if !exists {
		return nil, fmt.Errorf("no keys found for peer: %s", peerID)
	}

	// Check if algorithm exists
	key, found := keys[algorithm]
	if !found {
		return nil, fmt.Errorf("no key found for algorithm: %s", algorithm)
	}

	return key, nil
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
func (ks *KeyStore) ListKeys() ([]*KeyInfo, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	var keys []*KeyInfo
	for _, peerKeys := range ks.Keys {
		for _, key := range peerKeys {
			keys = append(keys, key)
		}
	}
	return keys, nil
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
func (ks *KeyStore) DeleteKey(keyID string) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Find and delete the key
	for peerID, peerKeys := range ks.Keys {
		for algorithm, key := range peerKeys {
			if key.PeerID == keyID {
				delete(peerKeys, algorithm)
				if len(peerKeys) == 0 {
					delete(ks.Keys, peerID)
				}
				return ks.Save()
			}
		}
	}

	return fmt.Errorf("key not found: %s", keyID)
}

// RotateKey rotates a key by generating a new one
func (ks *KeyStore) RotateKey(keyID string) (*KeyInfo, error) {
	// Find the old key
	ks.mutex.RLock()
	var oldKey *KeyInfo
	for _, peerKeys := range ks.Keys {
		for _, key := range peerKeys {
			if key.PeerID == keyID {
				oldKey = key
				break
			}
		}
		if oldKey != nil {
			break
		}
	}
	ks.mutex.RUnlock()

	if oldKey == nil {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Generate a new key
	newKey, err := ks.GenerateKey(oldKey.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	// Delete the old key
	if err := ks.DeleteKey(keyID); err != nil {
		return nil, fmt.Errorf("failed to delete old key: %w", err)
	}

	return newKey, nil
}

// BackupKeys exports all keys to a JSON format
func (ks *KeyStore) BackupKeys() ([]byte, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	return json.MarshalIndent(ks.Keys, "", "  ")
}

// RestoreKeys imports all keys from a JSON format
func (ks *KeyStore) RestoreKeys(data []byte) ([]*KeyInfo, error) {
	var keys map[string]map[string]*KeyInfo
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("failed to parse backup data: %w", err)
	}

	ks.mutex.Lock()
	ks.Keys = keys
	ks.mutex.Unlock()

	if err := ks.Save(); err != nil {
		return nil, fmt.Errorf("failed to save restored keys: %w", err)
	}

	// Return list of restored keys
	var keyList []*KeyInfo
	for _, peerKeys := range keys {
		for _, key := range peerKeys {
			keyList = append(keyList, key)
		}
	}

	return keyList, nil
}
