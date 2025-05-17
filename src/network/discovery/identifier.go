package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
)

// IdentifierRecord stores information about a peer associated with an identifier
type IdentifierRecord struct {
	Identifier string    `json:"identifier"` // Username, key ID, or custom identifier
	PeerID     string    `json:"peer_id"`    // The associated peer ID
	Type       string    `json:"type"`       // Type of identifier (username, key_id, custom)
	Timestamp  time.Time `json:"timestamp"`  // When this association was last updated
	KeyID      string    `json:"key_id"`     // Associated cryptographic key ID (if applicable)
	Metadata   []byte    `json:"metadata"`   // Additional metadata (JSON or binary)
}

// IdentifierStore manages the mappings between identifiers and peers
type IdentifierStore struct {
	Records     map[string]*IdentifierRecord `json:"records"`       // Maps identifier to record
	PeerToIdent map[string][]string          `json:"peer_to_ident"` // Maps peer ID to identifiers
	configDir   string
	configPath  string
	mu          sync.RWMutex
	initialized bool
}

// NewIdentifierStore creates a new identifier store
func NewIdentifierStore(configDir string) (*IdentifierStore, error) {
	store := &IdentifierStore{
		Records:     make(map[string]*IdentifierRecord),
		PeerToIdent: make(map[string][]string),
		configDir:   configDir,
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	store.configPath = filepath.Join(configDir, "identifiers.json")

	// Try to load existing identifiers
	if err := store.Load(); err != nil {
		// If file doesn't exist, just initialize an empty store
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load identifier store: %w", err)
		}

		// Save the empty store
		if err := store.Save(); err != nil {
			return nil, fmt.Errorf("failed to save identifier store: %w", err)
		}
	}

	store.initialized = true
	return store, nil
}

// Load loads identifiers from the configuration file
func (store *IdentifierStore) Load() error {
	data, err := os.ReadFile(store.configPath)
	if err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := json.Unmarshal(data, store); err != nil {
		return fmt.Errorf("failed to parse identifier store: %w", err)
	}

	// Rebuild the peer-to-identifier map
	store.PeerToIdent = make(map[string][]string)
	for ident, record := range store.Records {
		peerID := record.PeerID
		store.PeerToIdent[peerID] = append(store.PeerToIdent[peerID], ident)
	}

	return nil
}

// Save saves the identifiers to the configuration file
func (store *IdentifierStore) Save() error {
	store.mu.RLock()
	defer store.mu.RUnlock()

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identifier store: %w", err)
	}

	return os.WriteFile(store.configPath, data, 0644)
}

// AddIdentifier associates an identifier with a peer
func (store *IdentifierStore) AddIdentifier(identifier string, peerID string, identType string, keyID string, metadata []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	// Create the record
	record := &IdentifierRecord{
		Identifier: identifier,
		PeerID:     peerID,
		Type:       identType,
		Timestamp:  time.Now(),
		KeyID:      keyID,
		Metadata:   metadata,
	}

	// Add to the maps
	store.Records[identifier] = record
	store.PeerToIdent[peerID] = append(store.PeerToIdent[peerID], identifier)

	// Save if initialized
	if store.initialized {
		return store.Save()
	}

	return nil
}

// GetPeerByIdentifier looks up a peer by an identifier
func (store *IdentifierStore) GetPeerByIdentifier(identifier string) (string, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	record, exists := store.Records[identifier]
	if !exists {
		return "", fmt.Errorf("no peer found for identifier: %s", identifier)
	}

	return record.PeerID, nil
}

// GetIdentifiersByPeer gets all identifiers for a peer
func (store *IdentifierStore) GetIdentifiersByPeer(peerID string) []string {
	store.mu.RLock()
	defer store.mu.RUnlock()

	return store.PeerToIdent[peerID]
}

// RemoveIdentifier removes an identifier
func (store *IdentifierStore) RemoveIdentifier(identifier string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	record, exists := store.Records[identifier]
	if !exists {
		return fmt.Errorf("identifier not found: %s", identifier)
	}

	// Remove the identifier from the peer's list
	peerID := record.PeerID
	identifiers := store.PeerToIdent[peerID]
	for i, ident := range identifiers {
		if ident == identifier {
			// Remove this identifier
			identifiers = append(identifiers[:i], identifiers[i+1:]...)
			break
		}
	}

	// Update the peer map or delete if empty
	if len(identifiers) == 0 {
		delete(store.PeerToIdent, peerID)
	} else {
		store.PeerToIdent[peerID] = identifiers
	}

	// Remove from the main map
	delete(store.Records, identifier)

	// Save if initialized
	if store.initialized {
		return store.Save()
	}

	return nil
}

// FindByPrefix searches for identifiers with the given prefix
func (store *IdentifierStore) FindByPrefix(prefix string) []*IdentifierRecord {
	store.mu.RLock()
	defer store.mu.RUnlock()

	var results []*IdentifierRecord
	for identifier, record := range store.Records {
		if len(prefix) <= len(identifier) && identifier[:len(prefix)] == prefix {
			results = append(results, record)
		}
	}

	return results
}

// IdentifierDiscoveryService provides DHT-based discovery for user identifiers
type IdentifierDiscoveryService struct {
	host   host.Host
	dht    *dht.IpfsDHT
	store  *IdentifierStore
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// NewIdentifierDiscoveryService creates a new identifier-based discovery service
func NewIdentifierDiscoveryService(ctx context.Context, h host.Host, dht *dht.IpfsDHT, configDir string) (*IdentifierDiscoveryService, error) {
	// Create a cancellable context
	ctx, cancel := context.WithCancel(ctx)

	// Create or load the identifier store
	store, err := NewIdentifierStore(configDir)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create identifier store: %w", err)
	}

	return &IdentifierDiscoveryService{
		host:   h,
		dht:    dht,
		store:  store,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start begins the identifier discovery service
func (ids *IdentifierDiscoveryService) Start() error {
	// Start a background routine to periodically publish our identifiers to the DHT
	go ids.publishIdentifiers()

	return nil
}

// Stop halts the identifier discovery service
func (ids *IdentifierDiscoveryService) Stop() {
	ids.cancel()
}

// PublishIdentifier publishes an identifier to the DHT
func (ids *IdentifierDiscoveryService) PublishIdentifier(identifier string, identType string, keyID string, metadata []byte) error {
	// First, add to our local store
	peerID := ids.host.ID().String()
	if err := ids.store.AddIdentifier(identifier, peerID, identType, keyID, metadata); err != nil {
		return fmt.Errorf("failed to add identifier to store: %w", err)
	}

	// Then publish to DHT (using a namespaced key)
	dhtKey := ids.identifierToDHTKey(identifier)
	record := &IdentifierRecord{
		Identifier: identifier,
		PeerID:     peerID,
		Type:       identType,
		Timestamp:  time.Now(),
		KeyID:      keyID,
		Metadata:   metadata,
	}

	recordData, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	// Put the record in the DHT
	err = ids.dht.PutValue(ids.ctx, dhtKey, recordData)
	if err != nil {
		return fmt.Errorf("failed to publish identifier to DHT: %w", err)
	}

	return nil
}

// SearchIdentifier searches for an identifier in the DHT
func (ids *IdentifierDiscoveryService) SearchIdentifier(identifier string) ([]*IdentifierRecord, error) {
	// First check our local store
	localResults := ids.store.FindByPrefix(identifier)

	// Then search the DHT if we're looking for an exact match
	dhtKey := ids.identifierToDHTKey(identifier)

	// Try to get the value from the DHT
	recordData, err := ids.dht.GetValue(ids.ctx, dhtKey)
	if err == nil && len(recordData) > 0 {
		// Parse the record
		var record IdentifierRecord
		if err := json.Unmarshal(recordData, &record); err == nil {
			// Check if we already have this record locally
			found := false
			for _, localRecord := range localResults {
				if localRecord.Identifier == record.Identifier &&
					localRecord.PeerID == record.PeerID {
					found = true
					break
				}
			}

			// Add to results if not already present
			if !found {
				localResults = append(localResults, &record)
			}
		}
	}

	return localResults, nil
}

// identifierToDHTKey converts an identifier to a DHT key with proper namespace
func (ids *IdentifierDiscoveryService) identifierToDHTKey(identifier string) string {
	// Create a namespaced key to avoid conflicts with other DHT usages
	namespace := "/qasa/ident/"
	hasher := sha256.New()
	hasher.Write([]byte(namespace + identifier))
	hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	return namespace + hash
}

// publishIdentifiers periodically publishes all our identifiers to the DHT
func (ids *IdentifierDiscoveryService) publishIdentifiers() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ids.republishAllIdentifiers()
		case <-ids.ctx.Done():
			return
		}
	}
}

// republishAllIdentifiers republishes all identifiers associated with this peer
func (ids *IdentifierDiscoveryService) republishAllIdentifiers() {
	peerID := ids.host.ID().String()
	identifiers := ids.store.GetIdentifiersByPeer(peerID)

	for _, identifier := range identifiers {
		record := ids.store.Records[identifier]

		// Skip if this record doesn't belong to us (safety check)
		if record.PeerID != peerID {
			continue
		}

		// Republish to DHT
		dhtKey := ids.identifierToDHTKey(identifier)
		record.Timestamp = time.Now() // Update timestamp

		recordData, err := json.Marshal(record)
		if err != nil {
			continue
		}

		ids.dht.PutValue(ids.ctx, dhtKey, recordData)
	}
}

// SetSelfIdentifier sets and publishes the node's own identifier
func (ids *IdentifierDiscoveryService) SetSelfIdentifier(username string, keyID string, metadata []byte) error {
	return ids.PublishIdentifier(username, "username", keyID, metadata)
}

// RegisterKeyIdentifier associates a cryptographic key ID with this peer
func (ids *IdentifierDiscoveryService) RegisterKeyIdentifier(keyID string, metadata []byte) error {
	return ids.PublishIdentifier(keyID, "key_id", keyID, metadata)
}

// FindUserByName searches for users by username
func (ids *IdentifierDiscoveryService) FindUserByName(username string) ([]*IdentifierRecord, error) {
	return ids.SearchIdentifier(username)
}

// FindUserByKeyID searches for users by their key ID
func (ids *IdentifierDiscoveryService) FindUserByKeyID(keyID string) ([]*IdentifierRecord, error) {
	return ids.SearchIdentifier(keyID)
}
