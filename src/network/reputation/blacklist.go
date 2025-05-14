package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// BlacklistFile is the file where blacklisted peers are stored
	BlacklistFile = "blacklisted_peers.json"

	// Default blacklist values
	DefaultBlacklistDuration = 24 * time.Hour // 24 hours
)

// BlacklistReason represents the reason a peer was blacklisted
type BlacklistReason string

const (
	// ReasonManual means the peer was manually blacklisted by the user
	ReasonManual BlacklistReason = "manual"

	// ReasonBadReputation means the peer was blacklisted due to poor reputation
	ReasonBadReputation BlacklistReason = "bad_reputation"

	// ReasonSecurityViolation means the peer was blacklisted for security violations
	ReasonSecurityViolation BlacklistReason = "security_violation"

	// ReasonSpamming means the peer was blacklisted for spamming messages
	ReasonSpamming BlacklistReason = "spamming"

	// ReasonMaliciousBehavior means the peer was blacklisted for malicious behavior
	ReasonMaliciousBehavior BlacklistReason = "malicious_behavior"
)

// BlacklistedPeer represents a peer that has been blacklisted
type BlacklistedPeer struct {
	PeerID        string          `json:"peer_id"`
	BlacklistedAt time.Time       `json:"blacklisted_at"`
	ExpiresAt     time.Time       `json:"expires_at,omitempty"` // Optional expiry time
	Reason        BlacklistReason `json:"reason"`
	Notes         string          `json:"notes,omitempty"`
	Permanent     bool            `json:"permanent"`
}

// BlacklistStore manages the list of blacklisted peers
type BlacklistStore struct {
	Blacklist       map[string]*BlacklistedPeer `json:"blacklist"`
	configDir       string
	configPath      string
	mutex           sync.RWMutex
	reputationStore *ReputationStore // Reference to reputation store for integration
}

// NewBlacklistStore creates a new blacklist store
func NewBlacklistStore(configDir string, reputationStore *ReputationStore) (*BlacklistStore, error) {
	bs := &BlacklistStore{
		Blacklist:       make(map[string]*BlacklistedPeer),
		configDir:       configDir,
		reputationStore: reputationStore,
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	bs.configPath = filepath.Join(configDir, BlacklistFile)

	// Try to load existing blacklist
	if err := bs.Load(); err != nil {
		// If file doesn't exist, initialize with empty blacklist
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load blacklist: %w", err)
		}
		// This is a new store, save empty state
		if err := bs.Save(); err != nil {
			return nil, fmt.Errorf("failed to save initial blacklist: %w", err)
		}
	}

	return bs, nil
}

// Load loads the blacklist from the configuration file
func (bs *BlacklistStore) Load() error {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	data, err := os.ReadFile(bs.configPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, bs)
}

// Save saves the blacklist to the configuration file
func (bs *BlacklistStore) Save() error {
	bs.mutex.RLock()
	defer bs.mutex.RUnlock()

	data, err := json.MarshalIndent(bs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blacklist: %w", err)
	}

	return os.WriteFile(bs.configPath, data, 0644)
}

// BlacklistPeer adds a peer to the blacklist for a specific duration
// If duration is 0, the blacklisting is permanent
func (bs *BlacklistStore) BlacklistPeer(peerID peer.ID, reason BlacklistReason, notes string, duration time.Duration) error {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	peerIDStr := peerID.String()
	now := time.Now()

	permanent := duration == 0
	var expiresAt time.Time
	if !permanent {
		expiresAt = now.Add(duration)
	}

	bs.Blacklist[peerIDStr] = &BlacklistedPeer{
		PeerID:        peerIDStr,
		BlacklistedAt: now,
		ExpiresAt:     expiresAt,
		Reason:        reason,
		Notes:         notes,
		Permanent:     permanent,
	}

	// Update reputation if we have a reputation store
	if bs.reputationStore != nil {
		// Add a manual penalty event
		bs.reputationStore.RecordEvent(peerID, EventManualPenalty)
		// Add a note about blacklisting
		noteText := fmt.Sprintf("[BLACKLISTED] %s - Reason: %s, Notes: %s", now.Format(time.RFC3339), reason, notes)
		bs.reputationStore.AddNote(peerID, noteText)
	}

	return bs.Save()
}

// UnblacklistPeer removes a peer from the blacklist
func (bs *BlacklistStore) UnblacklistPeer(peerID peer.ID) error {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	peerIDStr := peerID.String()

	if _, exists := bs.Blacklist[peerIDStr]; !exists {
		return fmt.Errorf("peer %s is not blacklisted", peerIDStr)
	}

	delete(bs.Blacklist, peerIDStr)

	// Update reputation if we have a reputation store
	if bs.reputationStore != nil {
		// Add a note about unblacklisting
		noteText := fmt.Sprintf("[UNBLACKLISTED] %s", time.Now().Format(time.RFC3339))
		bs.reputationStore.AddNote(peerID, noteText)
	}

	return bs.Save()
}

// IsBlacklisted checks if a peer is currently blacklisted
func (bs *BlacklistStore) IsBlacklisted(peerID peer.ID) bool {
	bs.mutex.RLock()
	defer bs.mutex.RUnlock()

	peerIDStr := peerID.String()

	blacklistEntry, exists := bs.Blacklist[peerIDStr]
	if !exists {
		return false
	}

	// If the blacklisting is permanent, the peer is blacklisted
	if blacklistEntry.Permanent {
		return true
	}

	// If the blacklisting has expired, the peer is not blacklisted
	if time.Now().After(blacklistEntry.ExpiresAt) {
		// We'll clean this up in the cleanup routine
		return false
	}

	return true
}

// GetBlacklistInfo gets information about a blacklisted peer
func (bs *BlacklistStore) GetBlacklistInfo(peerID peer.ID) (*BlacklistedPeer, error) {
	bs.mutex.RLock()
	defer bs.mutex.RUnlock()

	peerIDStr := peerID.String()

	blacklistEntry, exists := bs.Blacklist[peerIDStr]
	if !exists {
		return nil, fmt.Errorf("peer %s is not blacklisted", peerIDStr)
	}

	// If the blacklisting has expired, the peer is not blacklisted
	if !blacklistEntry.Permanent && time.Now().After(blacklistEntry.ExpiresAt) {
		return nil, fmt.Errorf("peer %s blacklisting has expired", peerIDStr)
	}

	return blacklistEntry, nil
}

// GetAllBlacklistedPeers returns all currently blacklisted peers
func (bs *BlacklistStore) GetAllBlacklistedPeers() []peer.ID {
	bs.mutex.RLock()
	defer bs.mutex.RUnlock()

	now := time.Now()
	var blacklistedPeers []peer.ID

	for peerIDStr, blacklistEntry := range bs.Blacklist {
		// Skip expired entries
		if !blacklistEntry.Permanent && now.After(blacklistEntry.ExpiresAt) {
			continue
		}

		peerID, err := peer.Decode(peerIDStr)
		if err == nil {
			blacklistedPeers = append(blacklistedPeers, peerID)
		}
	}

	return blacklistedPeers
}

// ExtendBlacklisting extends the blacklisting duration for a peer
func (bs *BlacklistStore) ExtendBlacklisting(peerID peer.ID, duration time.Duration) error {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	peerIDStr := peerID.String()

	blacklistEntry, exists := bs.Blacklist[peerIDStr]
	if !exists {
		return fmt.Errorf("peer %s is not blacklisted", peerIDStr)
	}

	// Cannot extend permanent blacklisting
	if blacklistEntry.Permanent {
		return fmt.Errorf("peer %s is permanently blacklisted", peerIDStr)
	}

	// Extend the blacklisting
	blacklistEntry.ExpiresAt = blacklistEntry.ExpiresAt.Add(duration)

	// Update reputation if we have a reputation store
	if bs.reputationStore != nil {
		// Add a note about extended blacklisting
		noteText := fmt.Sprintf("[BLACKLIST_EXTENDED] %s - Extended by %s",
			time.Now().Format(time.RFC3339), duration.String())
		bs.reputationStore.AddNote(peerID, noteText)
	}

	return bs.Save()
}

// MakePermanent makes a temporary blacklisting permanent
func (bs *BlacklistStore) MakePermanent(peerID peer.ID) error {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	peerIDStr := peerID.String()

	blacklistEntry, exists := bs.Blacklist[peerIDStr]
	if !exists {
		return fmt.Errorf("peer %s is not blacklisted", peerIDStr)
	}

	// Already permanent
	if blacklistEntry.Permanent {
		return nil
	}

	// Make permanent
	blacklistEntry.Permanent = true
	blacklistEntry.ExpiresAt = time.Time{} // Zero time

	// Update reputation if we have a reputation store
	if bs.reputationStore != nil {
		// Add a note about permanent blacklisting
		noteText := fmt.Sprintf("[BLACKLIST_PERMANENT] %s - Changed to permanent",
			time.Now().Format(time.RFC3339))
		bs.reputationStore.AddNote(peerID, noteText)
	}

	return bs.Save()
}

// StartCleanupRoutine starts a goroutine to periodically clean up expired blacklist entries
func (bs *BlacklistStore) StartCleanupRoutine(ctx context.Context, cleanupInterval time.Duration) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				bs.cleanupExpiredEntries()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// cleanupExpiredEntries removes expired blacklist entries
func (bs *BlacklistStore) cleanupExpiredEntries() {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	now := time.Now()

	for peerIDStr, blacklistEntry := range bs.Blacklist {
		// Skip permanent entries
		if blacklistEntry.Permanent {
			continue
		}

		// Remove expired entries
		if now.After(blacklistEntry.ExpiresAt) {
			delete(bs.Blacklist, peerIDStr)
		}
	}

	bs.Save()
}

// BlacklistBadPeers automatically blacklists peers with poor reputation
func (bs *BlacklistStore) BlacklistBadPeers(threshold int, duration time.Duration) (int, error) {
	// Skip if we don't have a reputation store
	if bs.reputationStore == nil {
		return 0, fmt.Errorf("no reputation store available")
	}

	// Get all peers from reputation store
	badPeers := bs.reputationStore.GetBadPeers()

	count := 0
	for _, peerID := range badPeers {
		// Skip if already blacklisted
		if bs.IsBlacklisted(peerID) {
			continue
		}

		// Blacklist the peer
		score := bs.reputationStore.GetPeerScore(peerID)
		notes := fmt.Sprintf("Automatically blacklisted due to poor reputation score: %d", score)

		err := bs.BlacklistPeer(peerID, ReasonBadReputation, notes, duration)
		if err == nil {
			count++
		}
	}

	return count, nil
}

// SyncFromReputationStore syncs blacklist with reputation store based on thresholds
func (bs *BlacklistStore) SyncFromReputationStore(threshold int, duration time.Duration) (int, error) {
	return bs.BlacklistBadPeers(threshold, duration)
}
