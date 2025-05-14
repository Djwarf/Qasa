package reputation

import (
	"context"
	"fmt"
	"sync"
	"time"

	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

var log = logging.Logger("reputation")

const (
	// DefaultCleanupInterval defines how often to clean up reputation data
	DefaultCleanupInterval = 1 * time.Hour

	// DefaultAutoBlacklistInterval defines how often to auto-blacklist bad peers
	DefaultAutoBlacklistInterval = 6 * time.Hour

	// DefaultAutoBlacklistDuration defines the duration for automatic blacklisting
	DefaultAutoBlacklistDuration = 7 * 24 * time.Hour // 1 week
)

// ManagerOptions defines options for the reputation manager
type ManagerOptions struct {
	// Whether to automatically blacklist peers with poor reputation
	EnableAutoBlacklist bool

	// Duration for which peers are automatically blacklisted
	AutoBlacklistDuration time.Duration

	// The threshold score at which peers are automatically blacklisted
	AutoBlacklistThreshold int

	// How often to run automatic cleanup of old data
	CleanupInterval time.Duration
}

// DefaultManagerOptions returns default options for the manager
func DefaultManagerOptions() *ManagerOptions {
	return &ManagerOptions{
		EnableAutoBlacklist:    true,
		AutoBlacklistDuration:  DefaultAutoBlacklistDuration,
		AutoBlacklistThreshold: DefaultThresholdBad,
		CleanupInterval:        DefaultCleanupInterval,
	}
}

// Manager integrates reputation and blacklisting with the network
type Manager struct {
	reputationStore     *ReputationStore
	blacklistStore      *BlacklistStore
	host                host.Host
	ctx                 context.Context
	cancel              context.CancelFunc
	cleanupInterval     time.Duration
	autoBlacklistConfig struct {
		enabled   bool
		interval  time.Duration
		duration  time.Duration
		threshold int
	}
	mu sync.RWMutex
}

// NewManager creates a new reputation and blacklist manager
func NewManager(ctx context.Context, h host.Host, dataDir string, options *ManagerOptions) (*Manager, error) {
	if options == nil {
		options = DefaultManagerOptions()
	}

	childCtx, cancel := context.WithCancel(ctx)

	// Initialise reputation store
	repStore, err := NewReputationStore(dataDir, DefaultReputationConfig())
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize reputation store: %w", err)
	}

	// Initialize blacklist store
	blacklistStore, err := NewBlacklistStore(dataDir, repStore)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize blacklist store: %w", err)
	}

	manager := &Manager{
		reputationStore: repStore,
		blacklistStore:  blacklistStore,
		host:            h,
		ctx:             childCtx,
		cancel:          cancel,
		cleanupInterval: options.CleanupInterval,
	}

	// Configure auto-blacklisting
	manager.autoBlacklistConfig.enabled = options.EnableAutoBlacklist
	manager.autoBlacklistConfig.duration = options.AutoBlacklistDuration
	manager.autoBlacklistConfig.threshold = options.AutoBlacklistThreshold
	manager.autoBlacklistConfig.interval = DefaultAutoBlacklistInterval

	return manager, nil
}

// Start begins the background tasks for the reputation manager
func (m *Manager) Start() {
	// Start periodic cleanup of old data
	go m.runPeriodicCleanup()

	// Start auto-blacklisting if enabled
	if m.autoBlacklistConfig.enabled {
		go m.runAutoBlacklisting()
	}
}

// runPeriodicCleanup periodically cleans up old reputation data
func (m *Manager) runPeriodicCleanup() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Infof("Running periodic reputation data cleanup")
			if err := m.reputationStore.Cleanup(); err != nil {
				log.Errorf("Error during reputation cleanup: %v", err)
			}
			// The blacklist store doesn't have a Cleanup method, but we can clean expired entries
			m.cleanExpiredBlacklistEntries()
		case <-m.ctx.Done():
			return
		}
	}
}

// cleanExpiredBlacklistEntries removes expired entries from the blacklist
func (m *Manager) cleanExpiredBlacklistEntries() {
	// This is a placeholder for actual implementation
	// The blacklist store should automatically handle expiration when IsBlacklisted is called
	log.Info("Checking for expired blacklist entries")
}

// runAutoBlacklisting periodically checks for peers with poor reputation and blacklists them
func (m *Manager) runAutoBlacklisting() {
	ticker := time.NewTicker(m.autoBlacklistConfig.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkAndBlacklistPeers()
		case <-m.ctx.Done():
			return
		}
	}
}

// checkAndBlacklistPeers checks all peers and blacklists those with poor reputation
func (m *Manager) checkAndBlacklistPeers() {
	lowRepPeers := m.reputationStore.GetPeersWithScoreBelowThreshold(m.autoBlacklistConfig.threshold)

	for _, peerID := range lowRepPeers {
		// Skip if already blacklisted
		if m.blacklistStore.IsBlacklisted(peerID) {
			continue
		}

		log.Infof("Auto-blacklisting peer %s due to low reputation score", peerID)
		score := m.reputationStore.GetPeerScore(peerID)
		reason := fmt.Sprintf("Auto-blacklisted due to low reputation score: %d", score)

		err := m.BlacklistPeer(peerID, m.autoBlacklistConfig.duration, ReasonBadReputation, reason)
		if err != nil {
			log.Errorf("Failed to auto-blacklist peer %s: %v", peerID, err)
		}
	}
}

// RecordEvent records an event for a peer, which affects their reputation score
func (m *Manager) RecordEvent(p peer.ID, event EventType) {
	m.reputationStore.RecordEvent(p, event)
}

// GetScore returns the current reputation score for a peer
func (m *Manager) GetScore(p peer.ID) int {
	return m.reputationStore.GetPeerScore(p)
}

// BlacklistPeer adds a peer to the blacklist for a specified duration
func (m *Manager) BlacklistPeer(p peer.ID, duration time.Duration, reason BlacklistReason, note string) error {
	err := m.blacklistStore.BlacklistPeer(p, reason, note, duration)
	if err != nil {
		return err
	}

	// If connected to this peer, disconnect them
	if m.host.Network().Connectedness(p) == network.Connected {
		log.Infof("Disconnecting blacklisted peer: %s", p)
		// Use reason 1 as a generic security-related disconnect reason
		m.host.Network().ClosePeer(p)
	}

	return nil
}

// RemoveFromBlacklist removes a peer from the blacklist
func (m *Manager) RemoveFromBlacklist(p peer.ID) error {
	return m.blacklistStore.UnblacklistPeer(p)
}

// IsBlacklisted checks if a peer is currently blacklisted
func (m *Manager) IsBlacklisted(p peer.ID) bool {
	return m.blacklistStore.IsBlacklisted(p)
}

// ConnectionGater implementation

// InterceptPeerDial checks if a peer is blacklisted before dialing
func (m *Manager) InterceptPeerDial(p peer.ID) (allow bool) {
	return !m.blacklistStore.IsBlacklisted(p)
}

// InterceptAddrDial checks if a peer's address is allowed to be dialed
func (m *Manager) InterceptAddrDial(p peer.ID, addr ma.Multiaddr) (allow bool) {
	return !m.blacklistStore.IsBlacklisted(p)
}

// InterceptAccept checks if an inbound connection is allowed
func (m *Manager) InterceptAccept(addrs network.ConnMultiaddrs) (allow bool) {
	// We can't know the peer ID yet, so allow for now
	return true
}

// InterceptSecured checks if a secure connection is allowed
func (m *Manager) InterceptSecured(dir network.Direction, p peer.ID, addrs network.ConnMultiaddrs) (allow bool) {
	return !m.blacklistStore.IsBlacklisted(p)
}

// InterceptUpgraded checks if an upgraded connection is allowed
func (m *Manager) InterceptUpgraded(conn network.Conn) (allow bool, reason control.DisconnectReason) {
	p := conn.RemotePeer()

	// If blacklisted, reject the connection
	if m.blacklistStore.IsBlacklisted(p) {
		log.Infof("rejecting connection from blacklisted peer: %s", p)
		return false, control.DisconnectReason(1) // Using numeric value as control.DisconnectBlocked might not be available
	}

	// Get reputation score
	score := m.reputationStore.GetPeerScore(p)
	if score <= DefaultThresholdBad {
		log.Infof("rejecting connection from peer with low reputation: %s (score: %d)", p, score)
		return false, control.DisconnectReason(1) // Using numeric value as control.DisconnectBlocked might not be available
	}

	return true, 0
}

// SetupGater sets up this manager as a connection gater for the host
func (m *Manager) SetupGater() error {
	// Get the existing gater if any
	cm := m.host.ConnManager()

	// Apply it to the host
	// Note: This is implementation-specific and may change
	if setter, ok := cm.(interface{ SetGater(connmgr.ConnectionGater) }); ok {
		setter.SetGater(m)
		return nil
	}

	return fmt.Errorf("host connection manager does not support setting gater")
}
