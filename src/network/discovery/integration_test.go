package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGeoOptimizationIntegration tests the integration between geographic optimization
// and peer discovery mechanisms
func TestGeoOptimizationIntegration(t *testing.T) {
	// Skip in CI environments or short tests as this depends on mocks
	if testing.Short() {
		t.Skip("Skipping geo optimization integration test in short mode")
	}

	// Create test hosts
	hosts := setupTestHosts(t, 3)

	// Connect nodes to establish the topology
	connectHosts(t, hosts[0], hosts[1])
	connectHosts(t, hosts[0], hosts[2])

	// Create geo filter with mock locations
	geoFilter, err := createMockGeoFilter(t)
	require.NoError(t, err)

	// Inject mock locations for each peer
	mockHost1Location := &GeoLocation{
		IP:        "192.168.1.1",
		Country:   "US",
		Region:    "CA",
		City:      "Oakland",
		Latitude:  37.8044,
		Longitude: -122.2712,
		TimeZone:  "America/Los_Angeles",
		ISP:       "Test ISP",
		Cached:    true,
		FetchTime: time.Now(),
	}

	mockHost2Location := &GeoLocation{
		IP:        "192.168.1.2",
		Country:   "JP",
		Region:    "Tokyo",
		City:      "Tokyo",
		Latitude:  35.6762,
		Longitude: 139.6503,
		TimeZone:  "Asia/Tokyo",
		ISP:       "Tokyo ISP",
		Cached:    true,
		FetchTime: time.Now(),
	}

	// Add mock locations to cache
	addMockLocationForHost(t, geoFilter, hosts[1], "192.168.1.1", mockHost1Location)
	addMockLocationForHost(t, geoFilter, hosts[2], "192.168.1.2", mockHost2Location)

	// Test scoring peers
	host1Score, err := scorePeer(t, geoFilter, hosts[1])
	require.NoError(t, err)
	host2Score, err := scorePeer(t, geoFilter, hosts[2])
	require.NoError(t, err)

	// Host 1 (Oakland) should have a better score than Host 2 (Tokyo)
	assert.Greater(t, host1Score, host2Score, "Nearby peer should have higher score")

	// Test filtering peers
	peers := []peer.AddrInfo{
		{
			ID:    hosts[1].ID(),
			Addrs: hosts[1].Addrs(),
		},
		{
			ID:    hosts[2].ID(),
			Addrs: hosts[2].Addrs(),
		},
	}

	// Filter with a threshold between the two scores
	threshold := (host1Score + host2Score) / 2
	filteredPeers, err := geoFilter.FilterPeersByGeoScore(peers, threshold)
	require.NoError(t, err)

	// Only the nearby peer should pass the filter
	assert.Equal(t, 1, len(filteredPeers), "Only one peer should pass the filter")
	assert.Equal(t, hosts[1].ID(), filteredPeers[0].ID, "The nearby peer should be filtered in")

	// Test getting best peer
	bestPeers, err := geoFilter.GetBestNPeers(peers, 1)
	require.NoError(t, err)
	assert.Equal(t, 1, len(bestPeers), "Should return exactly one peer")
	assert.Equal(t, hosts[1].ID(), bestPeers[0].ID, "The nearby peer should be selected as best")
}

// TestGeoOptimizationWithDHT tests the integration between geographic optimization
// and DHT-based peer discovery
func TestGeoOptimizationWithDHT(t *testing.T) {
	// Skip in CI environments
	if testing.Short() {
		t.Skip("Skipping geo-DHT integration test in short mode")
	}

	// Create test hosts
	hosts := setupTestHosts(t, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create DHT services
	bootstrapAddrs := convertPeerInfosToMultiaddrs(t, []peer.AddrInfo{
		{
			ID:    hosts[0].ID(),
			Addrs: hosts[0].Addrs(),
		},
	})

	dht0, err := NewDHTService(ctx, hosts[0], nil)
	require.NoError(t, err)
	dht1, err := NewDHTService(ctx, hosts[1], bootstrapAddrs)
	require.NoError(t, err)
	dht2, err := NewDHTService(ctx, hosts[2], bootstrapAddrs)
	require.NoError(t, err)

	// Start DHT services
	require.NoError(t, dht0.Start())
	require.NoError(t, dht1.Start())
	require.NoError(t, dht2.Start())

	// Ensure peers are connected
	connectHosts(t, hosts[0], hosts[1])
	connectHosts(t, hosts[0], hosts[2])

	// Create geo filter with mock locations
	geoFilter, err := createMockGeoFilter(t)
	require.NoError(t, err)

	// Set mock locations
	addMockLocationForHost(t, geoFilter, hosts[1], "192.168.1.1", &GeoLocation{
		IP:        "192.168.1.1",
		Country:   "US",
		Region:    "CA",
		City:      "Oakland",
		Latitude:  37.8044,
		Longitude: -122.2712,
		TimeZone:  "America/Los_Angeles",
		ISP:       "Test ISP",
		Cached:    true,
		FetchTime: time.Now(),
	})

	addMockLocationForHost(t, geoFilter, hosts[2], "192.168.1.2", &GeoLocation{
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
	})

	// Wait for DHT to stabilize
	time.Sleep(1 * time.Second)

	// Create list of all peers that DHT0 knows about
	var knownPeers []peer.AddrInfo
	for _, peerID := range hosts[0].Network().Peers() {
		if peerID == hosts[0].ID() {
			continue // Skip self
		}

		addrs := hosts[0].Peerstore().Addrs(peerID)
		if len(addrs) > 0 {
			knownPeers = append(knownPeers, peer.AddrInfo{
				ID:    peerID,
				Addrs: addrs,
			})
		}
	}

	// Sort and filter peers by geo score
	geoScores, err := geoFilter.SortPeersByGeoScore(knownPeers)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(geoScores), 1, "Should have scored at least one peer")

	// US peer should rank higher than AU peer
	if len(geoScores) >= 2 {
		usIdx := -1
		auIdx := -1

		// Find the indices of US and AU peers
		for i, score := range geoScores {
			loc, err := geoFilter.GetPeerLocation(score.PeerID, nil)
			if err != nil {
				continue
			}

			if loc.Country == "US" {
				usIdx = i
			} else if loc.Country == "AU" {
				auIdx = i
			}
		}

		// Verify US peer ranks higher than AU peer (lower index in sorted list)
		if usIdx >= 0 && auIdx >= 0 {
			assert.Less(t, usIdx, auIdx, "US peer should have higher geo score than AU peer")
		}
	}

	// Cleanup
	dht0.Stop()
	dht1.Stop()
	dht2.Stop()
}

// Helper function to connect two libp2p hosts
func connectHosts(t *testing.T, a, b host.Host) {
	peerInfo := peer.AddrInfo{
		ID:    b.ID(),
		Addrs: b.Addrs(),
	}
	err := a.Connect(context.Background(), peerInfo)
	require.NoError(t, err)

	// Verify connection
	assert.Contains(t, a.Network().Peers(), b.ID())
	assert.Contains(t, b.Network().Peers(), a.ID())
}

// Helper function to create a geo filter with a mock self location
func createMockGeoFilter(t *testing.T) (*GeoFilter, error) {
	options := DefaultGeoFilterOptions()
	filter, err := NewGeoFilter(options)
	if err != nil {
		return nil, err
	}

	// Set a mock location for self (San Francisco)
	filter.selfLocation = &GeoLocation{
		IP:        "127.0.0.1",
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

	return filter, nil
}

// Helper function to add a mock location for a host
func addMockLocationForHost(t *testing.T, filter *GeoFilter, h host.Host, ip string, location *GeoLocation) {
	filter.cacheMutex.Lock()
	defer filter.cacheMutex.Unlock()

	filter.cache[ip] = location

	// Also add a mapping from multiaddrs to this IP for extraction
	for _, addr := range h.Addrs() {
		addrStr := addr.String()
		if len(addrStr) > 0 {
			// This is a trick for testing - we're hijacking the multiaddr extraction
			// to return our mock IP regardless of the actual multiaddr
			filter.cache[addrStr] = location
		}
	}
}

// Helper function to score a peer with the geo filter
func scorePeer(t *testing.T, filter *GeoFilter, h host.Host) (float64, error) {
	score, err := filter.ScorePeer(h.ID(), h.Addrs())
	if err != nil {
		return 0, err
	}
	return score.Score, nil
}
