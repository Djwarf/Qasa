package libp2p

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/qasa/network/reputation"
)

// ReputationManagerOptions contains configuration options for the reputation manager
type ReputationManagerOptions struct {
	// Data directory where reputation scores and blacklist are stored
	DataDir string

	// Whether to automatically blacklist peers with poor reputation
	EnableAutoBlacklist bool

	// Duration for which peers are automatically blacklisted
	AutoBlacklistDuration time.Duration

	// The threshold score at which peers are automatically blacklisted
	AutoBlacklistThreshold int
}

// DefaultReputationManagerOptions returns a default configuration
func DefaultReputationManagerOptions() *ReputationManagerOptions {
	return &ReputationManagerOptions{
		DataDir:                "reputation",
		EnableAutoBlacklist:    true,
		AutoBlacklistDuration:  24 * time.Hour, // 1 day by default
		AutoBlacklistThreshold: reputation.DefaultThresholdBad,
	}
}

// EnableReputationManager adds a reputation manager to the node
func (n *Node) EnableReputationManager(options *ReputationManagerOptions) error {
	if options == nil {
		options = DefaultReputationManagerOptions()
	}

	// Create the full data directory path
	dataDir := filepath.Join(n.configDir, options.DataDir)

	// Create a new reputation manager
	repManager, err := reputation.NewManager(
		n.ctx,
		n.host,
		dataDir,
		&reputation.ManagerOptions{
			EnableAutoBlacklist:    options.EnableAutoBlacklist,
			AutoBlacklistDuration:  options.AutoBlacklistDuration,
			AutoBlacklistThreshold: options.AutoBlacklistThreshold,
		},
	)

	if err != nil {
		return fmt.Errorf("failed to create reputation manager: %w", err)
	}

	// Store the reputation manager in the node
	n.repManager = repManager

	// Start the manager
	repManager.Start()

	// Set up the connection gater
	if err := repManager.SetupGater(); err != nil {
		return fmt.Errorf("failed to set up connection gater: %w", err)
	}

	fmt.Printf("Reputation manager initialized with data directory: %s\n", dataDir)
	return nil
}

// RecordPeerEvent records a reputation event for a peer
func (n *Node) RecordPeerEvent(p peer.ID, event reputation.EventType) {
	if n.repManager == nil {
		return
	}

	n.repManager.RecordEvent(p, event)
}

// GetPeerScore gets the reputation score for a peer
func (n *Node) GetPeerScore(p peer.ID) int {
	if n.repManager == nil {
		return 0
	}

	return n.repManager.GetScore(p)
}

// BlacklistPeer blacklists a peer for a specified duration
func (n *Node) BlacklistPeer(p peer.ID, duration time.Duration, reason string) error {
	if n.repManager == nil {
		return fmt.Errorf("reputation manager not enabled")
	}

	return n.repManager.BlacklistPeer(p, duration, reputation.ReasonManual, reason)
}

// RemoveFromBlacklist removes a peer from the blacklist
func (n *Node) RemoveFromBlacklist(p peer.ID) error {
	if n.repManager == nil {
		return fmt.Errorf("reputation manager not enabled")
	}

	return n.repManager.RemoveFromBlacklist(p)
}

// IsBlacklisted checks if a peer is blacklisted
func (n *Node) IsBlacklisted(p peer.ID) bool {
	if n.repManager == nil {
		return false
	}

	return n.repManager.IsBlacklisted(p)
}
