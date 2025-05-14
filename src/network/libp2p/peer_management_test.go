package libp2p

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/qasa/network/reputation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestNodes creates multiple QaSa nodes for testing
func setupTestNodes(t *testing.T, n int) []*Node {
	nodes := make([]*Node, n)

	for i := 0; i < n; i++ {
		ctx := context.Background()

		// Create a configuration for the node
		config := DefaultNodeConfig()
		config.ListenPort = 10000 + i
		config.EnableMDNS = false      // Disable mDNS for predictable testing
		config.EnableDHT = false       // Disable DHT for predictable testing
		config.ConfigDir = t.TempDir() // Use a temporary directory for each node

		// Create the node
		node, err := NewNodeWithConfig(ctx, config)
		require.NoError(t, err)

		nodes[i] = node

		// Clean up the node when test finishes
		t.Cleanup(func() {
			node.Close()
		})
	}

	return nodes
}

// connectNodes connects two nodes directly
func connectNodes(t *testing.T, a, b *Node) {
	// Add b's addresses to a's peerstore
	addrStrings := b.Addrs()
	require.NotEmpty(t, addrStrings)

	// Parse multiaddresses
	addrs := make([]ma.Multiaddr, 0, len(addrStrings))
	for _, addrStr := range addrStrings {
		addr, err := ma.NewMultiaddr(addrStr)
		require.NoError(t, err)
		addrs = append(addrs, addr)
	}

	// Create the address info
	addrInfo := peer.AddrInfo{
		ID:    b.ID(),
		Addrs: addrs,
	}

	// Connect a to b
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := a.host.Connect(ctx, addrInfo)
	require.NoError(t, err)

	// Verify connection
	assert.Contains(t, a.Peers(), b.ID())
	assert.Contains(t, b.Peers(), a.ID())
}

// TestReputationSystem tests the peer reputation system
func TestReputationSystem(t *testing.T) {
	// Create test nodes
	nodes := setupTestNodes(t, 2)

	// Enable reputation management on the first node
	require.NoError(t, nodes[0].EnableReputationManager(nil))

	// Connect the nodes
	connectNodes(t, nodes[0], nodes[1])

	// Record a positive event for the second node
	// Using a mock positive event type for testing
	nodes[0].RecordPeerEvent(nodes[1].ID(), reputation.EventType("1"))

	// Get the score
	score := nodes[0].GetPeerScore(nodes[1].ID())
	assert.True(t, score > 0, "Reputation score should be positive after successful interaction")

	// Check the peer is not blacklisted
	blacklisted := nodes[0].IsBlacklisted(nodes[1].ID())
	assert.False(t, blacklisted, "Peer should not be blacklisted")

	// Now blacklist the peer
	require.NoError(t, nodes[0].BlacklistPeer(nodes[1].ID(), 1*time.Minute, "Test blacklisting"))

	// Verify blacklisted status
	blacklisted = nodes[0].IsBlacklisted(nodes[1].ID())
	assert.True(t, blacklisted, "Peer should be blacklisted")

	// Wait for disconnection due to blacklisting
	time.Sleep(1 * time.Second)

	// Verify peer is disconnected
	assert.NotContains(t, nodes[0].Peers(), nodes[1].ID())

	// Remove from blacklist
	require.NoError(t, nodes[0].RemoveFromBlacklist(nodes[1].ID()))

	// Verify no longer blacklisted
	blacklisted = nodes[0].IsBlacklisted(nodes[1].ID())
	assert.False(t, blacklisted, "Peer should no longer be blacklisted")
}

// TestGeoOptimization tests the geographic peer optimization
func TestGeoOptimization(t *testing.T) {
	// Skip test in CI or short mode as it depends on external services
	if testing.Short() {
		t.Skip("Skipping geo optimization test in short mode")
	}

	// Create test nodes
	nodes := setupTestNodes(t, 3)

	// Connect all nodes
	connectNodes(t, nodes[0], nodes[1])
	connectNodes(t, nodes[0], nodes[2])

	// Enable geo optimization on the first node
	geoOptions := DefaultGeoOptimizerOptions()
	// Set a short optimization interval for testing
	geoOptions.OptimizeInterval = 1 * time.Second
	// Set a very low max connections to force optimization decisions
	geoOptions.MaxConnections = 1

	require.NoError(t, nodes[0].EnableGeoOptimization(geoOptions))

	// Check that geo optimization is enabled
	assert.True(t, nodes[0].IsGeoOptimizationEnabled())

	// Wait for geo optimization to run
	time.Sleep(2 * time.Second)

	// We expect one of the peers to be disconnected due to MaxConnections=1
	// But we don't know which one, as that depends on actual geo data
	peerCount := len(nodes[0].Peers())
	assert.LessOrEqual(t, peerCount, 1, "Geo optimization should have limited connections")

	// Clean up
	nodes[0].DisableGeoOptimization()
	assert.False(t, nodes[0].IsGeoOptimizationEnabled())
}
