package reputation

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupReputationStore(t *testing.T) *ReputationStore {
	tempDir := t.TempDir()

	rs, err := NewReputationStore(tempDir, DefaultReputationConfig())
	require.NoError(t, err)
	require.NotNil(t, rs)

	return rs
}

func createMockPeerID(t *testing.T) peer.ID {
	id, err := peer.Decode("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")
	require.NoError(t, err)
	return id
}

func TestReputationStoreBasics(t *testing.T) {
	rs := setupReputationStore(t)
	peerID := createMockPeerID(t)

	// Test initial score
	score := rs.GetPeerScore(peerID)
	assert.Equal(t, DefaultInitialScore, score)

	// Test recording a good event
	err := rs.RecordEvent(peerID, EventMessageDelivered)
	require.NoError(t, err)

	// Check score improved
	score = rs.GetPeerScore(peerID)
	assert.Equal(t, DefaultInitialScore+EventScores[EventMessageDelivered], score)

	// Test recording a bad event
	err = rs.RecordEvent(peerID, EventMessageFailed)
	require.NoError(t, err)

	// Check score reflects both events
	expectedScore := DefaultInitialScore + EventScores[EventMessageDelivered] + EventScores[EventMessageFailed]
	score = rs.GetPeerScore(peerID)
	assert.Equal(t, expectedScore, score)

	// Test peer status
	status := rs.GetPeerStatus(peerID)
	assert.Equal(t, StatusNeutral, status)
}

func TestReputationStoreGoodBadPeers(t *testing.T) {
	rs := setupReputationStore(t)

	// Create multiple test peer IDs
	goodPeerID := createMockPeerID(t)
	badPeerID, err := peer.Decode("QmcqQ7T4YomeMgFKj7H4zJJ7DUficAwJUY7QbmACYMtSLB")
	require.NoError(t, err)
	neutralPeerID, err := peer.Decode("QmPKLVqQyAZdFreMiNnJiBjUH1HigzohY7oLBCi9YW2qvk")
	require.NoError(t, err)

	// Set up a good peer
	for i := 0; i < 10; i++ {
		err = rs.RecordEvent(goodPeerID, EventKeyExchangeSuccessful)
		require.NoError(t, err)
	}

	// Set up a bad peer
	for i := 0; i < 5; i++ {
		err = rs.RecordEvent(badPeerID, EventInvalidMessage)
		require.NoError(t, err)
	}

	// Set up a neutral peer
	err = rs.RecordEvent(neutralPeerID, EventMessageDelivered)
	require.NoError(t, err)
	err = rs.RecordEvent(neutralPeerID, EventMessageFailed)
	require.NoError(t, err)

	// Get good peers
	goodPeers := rs.GetGoodPeers()
	assert.Contains(t, goodPeers, goodPeerID)
	assert.NotContains(t, goodPeers, badPeerID)
	assert.NotContains(t, goodPeers, neutralPeerID)

	// Get bad peers
	badPeers := rs.GetBadPeers()
	assert.Contains(t, badPeers, badPeerID)
	assert.NotContains(t, badPeers, goodPeerID)
	assert.NotContains(t, badPeers, neutralPeerID)
}

func TestReputationDecay(t *testing.T) {
	// Set up reputation store with shortened decay time for testing
	tempDir := t.TempDir()
	rs, err := NewReputationStore(tempDir, DefaultReputationConfig())
	require.NoError(t, err)

	// Override decay settings for testing
	rs.decayTime = 1 * time.Second
	rs.decayPercentage = 0.5 // 50% decay for dramatic effect in tests

	peerID := createMockPeerID(t)

	// Set up a high score
	err = rs.RecordEvent(peerID, EventManualBoost)
	require.NoError(t, err)

	initialScore := rs.GetPeerScore(peerID)
	assert.Equal(t, DefaultInitialScore+EventScores[EventManualBoost], initialScore)

	// Wait for decay time to pass
	time.Sleep(2 * time.Second)

	// Force decay by updating
	err = rs.UpdateLastSeen(peerID)
	require.NoError(t, err)

	// Check decayed score
	decayedScore := rs.GetPeerScore(peerID)
	assert.Less(t, decayedScore, initialScore)

	// Another test with negative scores
	badPeerID, err := peer.Decode("QmcqQ7T4YomeMgFKj7H4zJJ7DUficAwJUY7QbmACYMtSLB")
	require.NoError(t, err)

	// Set up a negative score
	err = rs.RecordEvent(badPeerID, EventManualPenalty)
	require.NoError(t, err)

	initialBadScore := rs.GetPeerScore(badPeerID)
	assert.Less(t, initialBadScore, 0)

	// Wait for decay time to pass
	time.Sleep(2 * time.Second)

	// Force decay by updating
	err = rs.UpdateLastSeen(badPeerID)
	require.NoError(t, err)

	// Check decayed score (should be closer to zero)
	decayedBadScore := rs.GetPeerScore(badPeerID)
	assert.Greater(t, decayedBadScore, initialBadScore)
}

func TestBlacklistStore(t *testing.T) {
	tempDir := t.TempDir()

	// Create reputation store for integration with blacklist
	rs, err := NewReputationStore(tempDir, DefaultReputationConfig())
	require.NoError(t, err)

	// Create blacklist store
	bs, err := NewBlacklistStore(tempDir, rs)
	require.NoError(t, err)

	peerID := createMockPeerID(t)

	// Verify peer is not blacklisted initially
	assert.False(t, bs.IsBlacklisted(peerID))

	// Blacklist the peer
	err = bs.BlacklistPeer(peerID, ReasonManual, "Test blacklisting", 1*time.Minute)
	require.NoError(t, err)

	// Verify peer is now blacklisted
	assert.True(t, bs.IsBlacklisted(peerID))

	// Get blacklist info
	info, err := bs.GetBlacklistInfo(peerID)
	require.NoError(t, err)
	assert.Equal(t, peerID.String(), info.PeerID)
	assert.Equal(t, ReasonManual, info.Reason)
	assert.False(t, info.Permanent)

	// Verify permanent blacklisting
	permanentPeerID, err := peer.Decode("QmPKLVqQyAZdFreMiNnJiBjUH1HigzohY7oLBCi9YW2qvk")
	require.NoError(t, err)

	err = bs.BlacklistPeer(permanentPeerID, ReasonSecurityViolation, "Permanent ban", 0)
	require.NoError(t, err)

	info, err = bs.GetBlacklistInfo(permanentPeerID)
	require.NoError(t, err)
	assert.True(t, info.Permanent)

	// Test expiration by creating a short ban
	shortBanPeerID, err := peer.Decode("QmR8xT7WfePCUXu8osNf7dTa4tRRKCaD9CEneDvP3q3xK4")
	require.NoError(t, err)

	err = bs.BlacklistPeer(shortBanPeerID, ReasonSpamming, "Short ban", 10*time.Millisecond)
	require.NoError(t, err)

	// Initially blacklisted
	assert.True(t, bs.IsBlacklisted(shortBanPeerID))

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should no longer be blacklisted
	assert.False(t, bs.IsBlacklisted(shortBanPeerID))
}

func TestManagerIntegration(t *testing.T) {
	tempDir := t.TempDir()

	// Create a new manager with test options
	options := &ManagerOptions{
		EnableAutoBlacklist:    true,
		AutoBlacklistDuration:  1 * time.Second,
		AutoBlacklistThreshold: -10, // Easier to trigger in tests
		CleanupInterval:        1 * time.Second,
	}

	// We can't use real libp2p host in unit tests, so we'll focus on the store operations
	// The host interactions are tested in the peer_management_test.go integration tests

	repStore, err := NewReputationStore(tempDir, DefaultReputationConfig())
	require.NoError(t, err)

	blacklistStore, err := NewBlacklistStore(tempDir, repStore)
	require.NoError(t, err)

	// Simulate the manager's operations manually
	peerID := createMockPeerID(t)

	// Record a severe penalty event
	repStore.RecordEvent(peerID, EventInvalidMessage)
	repStore.RecordEvent(peerID, EventInvalidMessage)
	repStore.RecordEvent(peerID, EventInvalidMessage)

	// Get the current score
	score := repStore.GetPeerScore(peerID)
	assert.True(t, score < options.AutoBlacklistThreshold, "Score should be below auto-blacklist threshold")

	// Verify peer would be auto-blacklisted
	badPeers := repStore.GetPeersWithScoreBelowThreshold(options.AutoBlacklistThreshold)
	assert.Contains(t, badPeers, peerID)

	// Test blacklisting directly
	err = blacklistStore.BlacklistPeer(peerID, ReasonBadReputation, "Auto-blacklisted in test", options.AutoBlacklistDuration)
	require.NoError(t, err)

	// Check blacklist status
	assert.True(t, blacklistStore.IsBlacklisted(peerID))

	// Wait for expiration
	time.Sleep(options.AutoBlacklistDuration + 10*time.Millisecond)

	// Should no longer be blacklisted
	assert.False(t, blacklistStore.IsBlacklisted(peerID))
}
