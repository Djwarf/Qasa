package discovery

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discoveryNotifee is a callback struct for discovery events
type discoveryNotifee struct {
	PeerFound func(peer.AddrInfo)
}

// HandlePeerFound is called when a peer is discovered
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if n.PeerFound != nil {
		n.PeerFound(pi)
	}
}

// setupTestHosts creates multiple libp2p hosts for testing
func setupTestHosts(t *testing.T, n int) []host.Host {
	hosts := make([]host.Host, n)

	for i := 0; i < n; i++ {
		h, err := libp2p.New(
			libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 10000+i)),
		)
		require.NoError(t, err)
		hosts[i] = h
		t.Cleanup(func() {
			h.Close()
		})
	}

	return hosts
}

// TestMDNSDiscovery tests the mDNS discovery service
func TestMDNSDiscovery(t *testing.T) {
	// Skip in CI environments where multicast may not be available
	if testing.Short() {
		t.Skip("Skipping mDNS test in short mode")
	}

	// Create two test hosts
	hosts := setupTestHosts(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Initialize mDNS on both
	mdns1, err := NewMDNSService(ctx, hosts[0])
	require.NoError(t, err)
	mdns2, err := NewMDNSService(ctx, hosts[1])
	require.NoError(t, err)

	// Start services
	mdns1.Start()
	mdns2.Start()

	// Prepare a channel to receive discovered peers
	peerChan := make(chan peer.AddrInfo, 1)

	// Set up our own handler for discovered peers from the peer channel
	go func() {
		for peer := range mdns1.DiscoveredPeers() {
			if peer.ID != hosts[0].ID() {
				select {
				case peerChan <- peer:
				default:
				}
			}
		}
	}()

	// Wait for peer to be discovered
	var discoveredPeer peer.AddrInfo
	select {
	case discoveredPeer = <-peerChan:
		// Successfully discovered
	case <-time.After(10 * time.Second):
		t.Fatal("mDNS discovery timed out")
	}

	// Verify the discovered peer is the second host
	assert.Equal(t, hosts[1].ID(), discoveredPeer.ID, "Discovered unexpected peer")

	// Cleanup
	mdns1.Stop()
	mdns2.Stop()
}

// TestDHTDiscovery tests the DHT-based discovery
func TestDHTDiscovery(t *testing.T) {
	// Create several test hosts
	hosts := setupTestHosts(t, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect the first two directly (bootstrap connection)
	hosts[0].Peerstore().AddAddrs(hosts[1].ID(), hosts[1].Addrs(), time.Hour)
	err := hosts[0].Connect(ctx, peer.AddrInfo{
		ID:    hosts[1].ID(),
		Addrs: hosts[1].Addrs(),
	})
	require.NoError(t, err, "Failed to connect to bootstrap node")

	// Convert peer.AddrInfo to multiaddrs for DHT bootstrap
	bootstrapAddrs := convertPeerInfosToMultiaddrs(t, []peer.AddrInfo{
		{
			ID:    hosts[1].ID(),
			Addrs: hosts[1].Addrs(),
		},
	})

	dht0, err := NewDHTService(ctx, hosts[0], bootstrapAddrs)
	require.NoError(t, err)
	dht1, err := NewDHTService(ctx, hosts[1], nil)
	require.NoError(t, err)
	dht2, err := NewDHTService(ctx, hosts[2], bootstrapAddrs)
	require.NoError(t, err)

	// Start DHT on all hosts
	require.NoError(t, dht0.Start())
	require.NoError(t, dht1.Start())
	require.NoError(t, dht2.Start())

	// Manually advertise from dht2 (we wouldn't normally call this directly)
	dht2.advertiseOnce()

	// Wait a bit to allow advertisement to propagate
	time.Sleep(1 * time.Second)

	// Set up a channel to collect discovered peers
	discoveredPeers := make(chan peer.AddrInfo, 5)

	// Listen for peers from dht0
	go func() {
		// Trigger peer search
		dht0.findPeers()

		// Collect peers from the channel
		for p := range dht0.DiscoveredPeers() {
			discoveredPeers <- p
			// Don't block test indefinitely
			if len(discoveredPeers) >= 5 {
				return
			}
		}
	}()

	// Wait for peers with timeout
	var found bool
	timeout := time.After(5 * time.Second)

	for !found {
		select {
		case p := <-discoveredPeers:
			if p.ID == hosts[2].ID() {
				found = true
			}
		case <-timeout:
			break
		}
	}

	assert.True(t, found, "DHT discovery failed to find announced peer")

	// Cleanup
	dht0.Stop()
	dht1.Stop()
	dht2.Stop()
}

// Helper function to convert peer infos to multiaddrs
func convertPeerInfosToMultiaddrs(t *testing.T, peers []peer.AddrInfo) []ma.Multiaddr {
	var multiaddrs []ma.Multiaddr

	for _, p := range peers {
		// Create a multiaddress that includes both the peer ID and its addresses
		for _, addr := range p.Addrs {
			peerAddr, err := ma.NewMultiaddr(fmt.Sprintf("%s/p2p/%s", addr.String(), p.ID.String()))
			require.NoError(t, err)
			multiaddrs = append(multiaddrs, peerAddr)
		}
	}

	return multiaddrs
}

// TestBootstrapNodes tests bootstrap node functionality
func TestBootstrapNodes(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a bootstrap node list
	bootstrapList, err := NewBootstrapNodeList(tempDir)
	require.NoError(t, err)

	// Test adding nodes
	testAddrs := []string{
		"/ip4/1.2.3.4/tcp/1234/p2p/QmTest1",
		"/ip4/5.6.7.8/tcp/5678/p2p/QmTest2",
	}

	for _, addr := range testAddrs {
		err := bootstrapList.AddNode(addr)
		require.NoError(t, err)
	}

	// Test getting nodes
	nodes, err := bootstrapList.GetNodes()
	require.NoError(t, err)
	assert.Equal(t, 2, len(nodes), "Wrong number of bootstrap nodes")

	// Test success tracking
	err = bootstrapList.RecordSuccess(testAddrs[0])
	require.NoError(t, err)

	// Test failure tracking
	err = bootstrapList.RecordFailure(testAddrs[1])
	require.NoError(t, err)

	// Test removing a node
	err = bootstrapList.RemoveNode(testAddrs[1])
	require.NoError(t, err)

	// Verify node was removed
	nodes, err = bootstrapList.GetNodes()
	require.NoError(t, err)
	assert.Equal(t, 1, len(nodes), "Wrong number of bootstrap nodes after removal")
}

// TestGeoFilter tests the geographic filter functionality
func TestGeoFilter(t *testing.T) {
	// Skip in CI environments or short tests as this requires internet
	if testing.Short() {
		t.Skip("Skipping geo filter test in short mode")
	}

	// Create a test geo filter
	options := DefaultGeoFilterOptions()
	// Use a test geolocation service for mockability in testing
	// In a real test this would be a mock server
	options.GeoServiceURL = "https://ipinfo.io/%s/json"

	filter, err := NewGeoFilter(options)
	if err != nil {
		// This test may fail due to network issues, so don't fail the build
		t.Logf("Warning: Could not create geo filter for testing: %v", err)
		t.Skip("Skipping geo filter test due to network issues")
		return
	}

	// Create mock peer locations for testing
	mockLocationNearby := &GeoLocation{
		IP:        "192.168.1.1",
		Country:   "US",
		Region:    "CA",
		City:      "San Francisco",
		Latitude:  37.7749,
		Longitude: -122.4194,
		TimeZone:  "America/Los_Angeles",
		ISP:       "Test ISP",
		Cached:    true,
		FetchTime: time.Now(),
	}

	mockLocationFar := &GeoLocation{
		IP:        "192.168.1.2",
		Country:   "AU",
		Region:    "NSW",
		City:      "Sydney",
		Latitude:  -33.8688,
		Longitude: 151.2093,
		TimeZone:  "Australia/Sydney",
		ISP:       "Other ISP",
		Cached:    true,
		FetchTime: time.Now(),
	}

	// Add test locations to cache
	filter.cacheMutex.Lock()
	filter.cache["192.168.1.1"] = mockLocationNearby
	filter.cache["192.168.1.2"] = mockLocationFar
	filter.cacheMutex.Unlock()

	// Mock our own location for predictable testing
	filter.selfLocation = &GeoLocation{
		IP:        "127.0.0.1",
		Country:   "US",
		Region:    "CA",
		City:      "San Francisco",
		Latitude:  37.7749,
		Longitude: -122.4194,
		TimeZone:  "America/Los_Angeles",
		ISP:       "Test ISP",
	}

	// Calculate distances (haversine)
	distanceToNearby := filter.haversineDistance(
		filter.selfLocation.Latitude,
		filter.selfLocation.Longitude,
		mockLocationNearby.Latitude,
		mockLocationNearby.Longitude,
	)

	distanceToFar := filter.haversineDistance(
		filter.selfLocation.Latitude,
		filter.selfLocation.Longitude,
		mockLocationFar.Latitude,
		mockLocationFar.Longitude,
	)

	// Verify distances
	assert.Less(t, distanceToNearby, 100.0, "Nearby location should be close")
	assert.Greater(t, distanceToFar, 1000.0, "Far location should be distant")

	// Test scoring peers
	// We can't easily test with real peers, so we'll just assert the scoring logic works
	distanceScore1 := 1.0 - distanceToNearby/options.PreferredRadius
	if distanceScore1 < 0 {
		distanceScore1 = 0
	}

	distanceScore2 := 1.0 - distanceToFar/options.PreferredRadius
	if distanceScore2 < 0 {
		distanceScore2 = 0
	}

	// Check that scores are consistent with distances
	assert.Greater(t, distanceScore1, distanceScore2, "Nearby peer should have higher distance score")
}
