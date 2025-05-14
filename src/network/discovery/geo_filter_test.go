package discovery

import (
	"strconv"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestGeoFilter(t *testing.T) *GeoFilter {
	options := DefaultGeoFilterOptions()

	// In tests, we'll use mock data rather than real geolocation services
	filter, err := NewGeoFilter(options)
	if err != nil {
		t.Logf("Warning: Could not create geo filter: %v", err)
		t.Skip("Skipping geo filter test - could not create filter")
	}

	// Set a mock location for self
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

	return filter
}

func createMockAddrs(t *testing.T, ip string) []ma.Multiaddr {
	addr, err := ma.NewMultiaddr("/ip4/" + ip + "/tcp/1234")
	require.NoError(t, err)
	return []ma.Multiaddr{addr}
}

func createMockPeerWithLocation(t *testing.T, filter *GeoFilter, peerID string, ip string, location *GeoLocation) peer.ID {
	pid, err := peer.Decode(peerID)
	require.NoError(t, err)

	// Add to cache
	filter.cacheMutex.Lock()
	filter.cache[ip] = location
	filter.cacheMutex.Unlock()

	return pid
}

func TestGeoFilterScoring(t *testing.T) {
	filter := createTestGeoFilter(t)

	// Create test peer locations
	nearbyLocation := &GeoLocation{
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

	mediumLocation := &GeoLocation{
		IP:        "192.168.1.2",
		Country:   "US",
		Region:    "NY",
		City:      "New York",
		Latitude:  40.7128,
		Longitude: -74.0060,
		TimeZone:  "America/New_York",
		ISP:       "Different ISP",
		Cached:    true,
		FetchTime: time.Now(),
	}

	farLocation := &GeoLocation{
		IP:        "192.168.1.3",
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

	// Create peers
	nearbyPeerID := createMockPeerWithLocation(t, filter,
		"QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
		"192.168.1.1", nearbyLocation)

	mediumPeerID := createMockPeerWithLocation(t, filter,
		"QmcqQ7T4YomeMgFKj7H4zJJ7DUficAwJUY7QbmACYMtSLB",
		"192.168.1.2", mediumLocation)

	farPeerID := createMockPeerWithLocation(t, filter,
		"QmPKLVqQyAZdFreMiNnJiBjUH1HigzohY7oLBCi9YW2qvk",
		"192.168.1.3", farLocation)

	// Test individual scoring
	nearbyAddrs := createMockAddrs(t, "192.168.1.1")
	nearbyScore, err := filter.ScorePeer(nearbyPeerID, nearbyAddrs)
	require.NoError(t, err)

	mediumAddrs := createMockAddrs(t, "192.168.1.2")
	mediumScore, err := filter.ScorePeer(mediumPeerID, mediumAddrs)
	require.NoError(t, err)

	farAddrs := createMockAddrs(t, "192.168.1.3")
	farScore, err := filter.ScorePeer(farPeerID, farAddrs)
	require.NoError(t, err)

	// Verify scores follow distance pattern
	assert.Greater(t, nearbyScore.Score, mediumScore.Score, "Nearby peer should have higher score than medium-distance peer")
	assert.Greater(t, mediumScore.Score, farScore.Score, "Medium-distance peer should have higher score than far peer")

	// Verify same ISP gives higher score
	assert.True(t, nearbyScore.SameISP, "Nearby peer should have same ISP")
	assert.False(t, mediumScore.SameISP, "Medium peer should have different ISP")
	assert.False(t, farScore.SameISP, "Far peer should have different ISP")

	// Verify distance calculations
	assert.Less(t, nearbyScore.Distance, 20.0, "Nearby peer should be close")
	assert.Greater(t, farScore.Distance, 10000.0, "Far peer should be very distant")
}

func TestGeoFilterSorting(t *testing.T) {
	filter := createTestGeoFilter(t)

	// Create test peer locations
	locations := map[string]*GeoLocation{
		"192.168.1.1": {
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
		},
		"192.168.1.2": {
			IP:        "192.168.1.2",
			Country:   "US",
			Region:    "NY",
			City:      "New York",
			Latitude:  40.7128,
			Longitude: -74.0060,
			TimeZone:  "America/New_York",
			ISP:       "Different ISP",
			Cached:    true,
			FetchTime: time.Now(),
		},
		"192.168.1.3": {
			IP:        "192.168.1.3",
			Country:   "AU",
			Region:    "NSW",
			City:      "Sydney",
			Latitude:  -33.8688,
			Longitude: 151.2093,
			TimeZone:  "Australia/Sydney",
			ISP:       "Other ISP",
			Cached:    true,
			FetchTime: time.Now(),
		},
		"192.168.1.4": {
			IP:        "192.168.1.4",
			Country:   "JP",
			Region:    "Tokyo",
			City:      "Tokyo",
			Latitude:  35.6762,
			Longitude: 139.6503,
			TimeZone:  "Asia/Tokyo",
			ISP:       "Tokyo ISP",
			Cached:    true,
			FetchTime: time.Now(),
		},
		"192.168.1.5": {
			IP:        "192.168.1.5",
			Country:   "DE",
			Region:    "Berlin",
			City:      "Berlin",
			Latitude:  52.5200,
			Longitude: 13.4050,
			TimeZone:  "Europe/Berlin",
			ISP:       "Berlin ISP",
			Cached:    true,
			FetchTime: time.Now(),
		},
	}

	// Add to cache
	for ip, location := range locations {
		filter.cacheMutex.Lock()
		filter.cache[ip] = location
		filter.cacheMutex.Unlock()
	}

	// Create peer infos
	peers := make([]peer.AddrInfo, 0, len(locations))
	for i, ip := range []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"} {
		// Create different peer IDs
		peerID, err := peer.Decode("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5" + strconv.Itoa(i))
		require.NoError(t, err)

		addr, err := ma.NewMultiaddr("/ip4/" + ip + "/tcp/1234")
		require.NoError(t, err)

		peers = append(peers, peer.AddrInfo{
			ID:    peerID,
			Addrs: []ma.Multiaddr{addr},
		})
	}

	// Test sorting
	sortedScores, err := filter.SortPeersByGeoScore(peers)
	require.NoError(t, err)
	assert.Len(t, sortedScores, len(peers), "Should return scores for all peers")

	// Verify sort order (highest score first)
	for i := 0; i < len(sortedScores)-1; i++ {
		assert.GreaterOrEqual(t, sortedScores[i].Score, sortedScores[i+1].Score,
			"Scores should be in descending order")
	}

	// Test filtering
	minScore := 0.3
	filteredPeers, err := filter.FilterPeersByGeoScore(peers, minScore)
	require.NoError(t, err)

	// We should have at least the nearby peers
	assert.True(t, len(filteredPeers) > 0, "Should have some peers above minimum score")
	assert.True(t, len(filteredPeers) <= len(peers), "Should not add new peers during filtering")

	// Test getting best N peers
	bestN := 2
	bestPeers, err := filter.GetBestNPeers(peers, bestN)
	require.NoError(t, err)
	assert.Len(t, bestPeers, bestN, "Should return exactly N best peers")
}

func TestGeoFilterExtractIP(t *testing.T) {
	filter := createTestGeoFilter(t)

	// Test IPv4 extraction
	addr, err := ma.NewMultiaddr("/ip4/192.168.1.1/tcp/1234")
	require.NoError(t, err)

	ip, err := filter.extractIP(addr)
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.1", ip)

	// Test IPv6 extraction
	addr, err = ma.NewMultiaddr("/ip6/2001:db8::1/tcp/1234")
	require.NoError(t, err)

	ip, err = filter.extractIP(addr)
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1", ip)

	// Test invalid address
	addr, err = ma.NewMultiaddr("/tcp/1234")
	require.NoError(t, err)

	_, err = filter.extractIP(addr)
	assert.Error(t, err, "Should error on address without IP")
}

func TestGeoFilterHaversine(t *testing.T) {
	filter := createTestGeoFilter(t)

	// San Francisco to New York: ~4,130 km
	sfLat, sfLon := 37.7749, -122.4194
	nyLat, nyLon := 40.7128, -74.0060

	distance := filter.haversineDistance(sfLat, sfLon, nyLat, nyLon)

	// Allow some margin of error due to different calculation methods
	assert.InDelta(t, 4130.0, distance, 100.0, "Distance from SF to NY should be ~4,130 km")

	// San Francisco to Oakland: ~12 km
	oaklandLat, oaklandLon := 37.8044, -122.2712

	distance = filter.haversineDistance(sfLat, sfLon, oaklandLat, oaklandLon)
	assert.InDelta(t, 12.0, distance, 5.0, "Distance from SF to Oakland should be ~12 km")
}
