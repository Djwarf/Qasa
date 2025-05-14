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

// GenerateDefaultKeys generates the default key pairs for the local node
func (ks *KeyStore) GenerateDefaultKeys() error {
	// Generate a local peer identity for networking
	_, pubKey, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return fmt.Errorf("failed to generate networking key: %w", err)
	}

	// Derive the peer ID from the public key
	peerID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to derive peer ID: %w", err)
	}

	peerIDStr := peerID.String()

	// Get the crypto provider
	provider, err := GetCryptoProvider()
	if err != nil {
		return fmt.Errorf("failed to get crypto provider: %w", err)
	}

	// Generate a Kyber key pair for encryption
	kyberKey, err := provider.GenerateKeyPair("kyber768")
	if err != nil {
		return fmt.Errorf("failed to generate Kyber key pair: %w", err)
	}

	// Generate a Dilithium key pair for signing
	dilithiumKey, err := provider.GenerateKeyPair("dilithium3")
	if err != nil {
		return fmt.Errorf("failed to generate Dilithium key pair: %w", err)
	}

	// Store the keys
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Create map for this peer if it doesn't exist
	if _, exists := ks.Keys[peerIDStr]; !exists {
		ks.Keys[peerIDStr] = make(map[string]*KeyInfo)
	}

	// Store the Kyber key
	ks.Keys[peerIDStr]["kyber768"] = &KeyInfo{
		Algorithm:  "kyber768",
		PublicKey:  kyberKey.PublicKey,
		PrivateKey: kyberKey.PrivateKey,
		PeerID:     peerIDStr,
		CreatedAt:  time.Now(),
		IsLocal:    true,
	}

	// Store the Dilithium key
	ks.Keys[peerIDStr]["dilithium3"] = &KeyInfo{
		Algorithm:  "dilithium3",
		PublicKey:  dilithiumKey.PublicKey,
		PrivateKey: dilithiumKey.PrivateKey,
		PeerID:     peerIDStr,
		CreatedAt:  time.Now(),
		IsLocal:    true,
	}

	// Save the keys to disk
	return ks.Save()
}

// GetMyPeerID returns the peer ID of the local node
func (ks *KeyStore) GetMyPeerID() (string, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	// Find a local key
	for peerID, keys := range ks.Keys {
		for _, key := range keys {
			if key.IsLocal {
				return peerID, nil
			}
		}
	}

	return "", fmt.Errorf("no local keys found")
}

// GetMyKeyPair returns a key pair for the local node
func (ks *KeyStore) GetMyKeyPair(algorithm string) (KeyPair, error) {
	peerID, err := ks.GetMyPeerID()
	if err != nil {
		return KeyPair{}, err
	}

	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	// Get the key for this algorithm
	if keys, exists := ks.Keys[peerID]; exists {
		if key, found := keys[algorithm]; found && key.IsLocal {
			return KeyPair{
				PublicKey:  key.PublicKey,
				PrivateKey: key.PrivateKey,
				Algorithm:  algorithm,
			}, nil
		}
	}

	return KeyPair{}, fmt.Errorf("no local key found for algorithm: %s", algorithm)
}

// AddPeerKey adds a public key for a peer
func (ks *KeyStore) AddPeerKey(peerID, algorithm string, publicKey []byte) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Create map for this peer if it doesn't exist
	if _, exists := ks.Keys[peerID]; !exists {
		ks.Keys[peerID] = make(map[string]*KeyInfo)
	}

	// Store the key
	ks.Keys[peerID][algorithm] = &KeyInfo{
		Algorithm: algorithm,
		PublicKey: publicKey,
		PeerID:    peerID,
		CreatedAt: time.Now(),
		IsLocal:   false,
	}

	// Save the keys to disk
	return ks.Save()
}

// GetPublicKey retrieves a public key for a peer and algorithm
func (ks *KeyStore) GetPublicKey(peerID, algorithm string) ([]byte, error) {
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

	return key.PublicKey, nil
}

// HasPeerKey checks if a key exists for a peer and algorithm
func (ks *KeyStore) HasPeerKey(peerID, algorithm string) bool {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	if keys, exists := ks.Keys[peerID]; exists {
		_, found := keys[algorithm]
		return found
	}

	return false
}

// ListPeerIDs returns a list of all known peer IDs
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

	// Check if this is the local node
	if keys, exists := ks.Keys[peerID]; exists {
		for _, key := range keys {
			if key.IsLocal {
				return fmt.Errorf("cannot remove local node keys")
			}
		}
	}

	// Remove the peer
	delete(ks.Keys, peerID)

	// Save the keys to disk
	return ks.Save()
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

// AddLocalKey adds or updates a local key pair
func (ks *KeyStore) AddLocalKey(peerID, algorithm string, publicKey, privateKey []byte) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	// Create map for this peer if it doesn't exist
	if _, exists := ks.Keys[peerID]; !exists {
		ks.Keys[peerID] = make(map[string]*KeyInfo)
	}

	// Store or update the key
	ks.Keys[peerID][algorithm] = &KeyInfo{
		Algorithm:  algorithm,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		PeerID:     peerID,
		CreatedAt:  time.Now(),
		IsLocal:    true,
	}

	// Save the keys to disk
	return ks.Save()
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
func (ks *KeyStore) ImportKey(data []byte) (*KeyInfo, error) {
	var keyInfo KeyInfo
	if err := json.Unmarshal(data, &keyInfo); err != nil {
		return nil, fmt.Errorf("failed to parse key data: %w", err)
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
