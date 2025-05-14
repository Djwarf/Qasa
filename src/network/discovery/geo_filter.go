package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// GeoLocation represents geographical location data
type GeoLocation struct {
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	Region    string    `json:"region"`
	City      string    `json:"city"`
	Latitude  float64   `json:"lat"`
	Longitude float64   `json:"lon"`
	TimeZone  string    `json:"timezone"`
	ISP       string    `json:"isp"`
	Cached    bool      `json:"-"`
	FetchTime time.Time `json:"-"`
}

// GeoFilterOptions contains configuration for the geographic peer filter
type GeoFilterOptions struct {
	// Maximum acceptable latency in milliseconds
	MaxLatency int

	// The preferred radius in kilometers for local peers
	PreferredRadius float64

	// Weight factor for geographic distance in scoring
	DistanceWeight float64

	// Enable ISP-based optimization (prefer same ISP)
	PreferSameISP bool

	// Cache expiration time
	CacheExpiration time.Duration

	// Custom geolocation service URL format (with %s for IP)
	GeoServiceURL string
}

// DefaultGeoFilterOptions returns default geographic filter options
func DefaultGeoFilterOptions() *GeoFilterOptions {
	return &GeoFilterOptions{
		MaxLatency:      200,                         // 200ms max latency
		PreferredRadius: 500.0,                       // 500 km radius
		DistanceWeight:  0.7,                         // 70% weight to distance
		PreferSameISP:   true,                        // Prefer peers in same ISP
		CacheExpiration: 24 * time.Hour,              // Cache for 24 hours
		GeoServiceURL:   "https://ipinfo.io/%s/json", // Default geolocation service
	}
}

// GeoFilter provides geographic optimization for peer selection
type GeoFilter struct {
	options      *GeoFilterOptions
	cache        map[string]*GeoLocation
	selfLocation *GeoLocation
	cacheMutex   sync.RWMutex
}

// NewGeoFilter creates a new geographic peer filter
func NewGeoFilter(options *GeoFilterOptions) (*GeoFilter, error) {
	if options == nil {
		options = DefaultGeoFilterOptions()
	}

	gf := &GeoFilter{
		options: options,
		cache:   make(map[string]*GeoLocation),
	}

	// Get our own location
	selfLocation, err := gf.getOwnLocation()
	if err != nil {
		return gf, fmt.Errorf("warning: could not determine own location: %w", err)
	}

	gf.selfLocation = selfLocation
	return gf, nil
}

// getOwnLocation determines the node's own geographic location
func (gf *GeoFilter) getOwnLocation() (*GeoLocation, error) {
	// Try to get our public IP
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ip := strings.TrimSpace(string(ipBytes))

	// Get geolocation data
	location, err := gf.getIPLocation(ip)
	if err != nil {
		return nil, err
	}

	return location, nil
}

// getIPLocation gets geographical data for an IP address
func (gf *GeoFilter) getIPLocation(ip string) (*GeoLocation, error) {
	// Check cache first
	gf.cacheMutex.RLock()
	cachedLocation, exists := gf.cache[ip]
	gf.cacheMutex.RUnlock()

	if exists && time.Since(cachedLocation.FetchTime) < gf.options.CacheExpiration {
		return cachedLocation, nil
	}

	// Fetch from service
	url := fmt.Sprintf(gf.options.GeoServiceURL, ip)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var location GeoLocation
	err = json.NewDecoder(resp.Body).Decode(&location)
	if err != nil {
		return nil, err
	}

	location.IP = ip
	location.FetchTime = time.Now()
	location.Cached = true

	// Store in cache
	gf.cacheMutex.Lock()
	gf.cache[ip] = &location
	gf.cacheMutex.Unlock()

	return &location, nil
}

// extractIP extracts an IP address from a multiaddress
func (gf *GeoFilter) extractIP(addr ma.Multiaddr) (string, error) {
	ipComponent, err := addr.ValueForProtocol(ma.P_IP4)
	if err == nil {
		return ipComponent, nil
	}

	ipComponent, err = addr.ValueForProtocol(ma.P_IP6)
	if err == nil {
		return ipComponent, nil
	}

	// Try to extract a domain name and resolve it
	domainComponent, err := addr.ValueForProtocol(ma.P_DNS4)
	if err == nil {
		ips, err := net.LookupHost(domainComponent)
		if err == nil && len(ips) > 0 {
			return ips[0], nil
		}
	}

	domainComponent, err = addr.ValueForProtocol(ma.P_DNS6)
	if err == nil {
		ips, err := net.LookupHost(domainComponent)
		if err == nil && len(ips) > 0 {
			return ips[0], nil
		}
	}

	return "", fmt.Errorf("no IP address found in multiaddress: %s", addr)
}

// haversineDistance calculates the great-circle distance between two points
func (gf *GeoFilter) haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	// Earth's radius in kilometers
	const R = 6371.0

	// Convert latitude and longitude to radians
	lat1 = lat1 * math.Pi / 180.0
	lon1 = lon1 * math.Pi / 180.0
	lat2 = lat2 * math.Pi / 180.0
	lon2 = lon2 * math.Pi / 180.0

	// Haversine formula
	dLat := lat2 - lat1
	dLon := lon2 - lon1
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1)*math.Cos(lat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	distance := R * c

	return distance
}

// GeoScore represents a peer's geographic optimization score
type GeoScore struct {
	PeerID   peer.ID
	Distance float64      // Distance in kilometers
	Latency  int          // Estimated latency in milliseconds
	SameISP  bool         // Whether the peer is in the same ISP
	Score    float64      // Overall score (higher is better)
	Location *GeoLocation // The peer's location
}

// GetPeerLocation gets the geographic location of a peer
func (gf *GeoFilter) GetPeerLocation(p peer.ID, addrs []ma.Multiaddr) (*GeoLocation, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses for peer %s", p)
	}

	// Try each address until we find a valid IP
	for _, addr := range addrs {
		ip, err := gf.extractIP(addr)
		if err != nil {
			continue
		}

		location, err := gf.getIPLocation(ip)
		if err != nil {
			continue
		}

		return location, nil
	}

	return nil, fmt.Errorf("could not determine location for peer %s", p)
}

// ScorePeer calculates a geographic score for a peer
func (gf *GeoFilter) ScorePeer(p peer.ID, addrs []ma.Multiaddr) (*GeoScore, error) {
	if gf.selfLocation == nil {
		return nil, fmt.Errorf("own location not available")
	}

	location, err := gf.GetPeerLocation(p, addrs)
	if err != nil {
		return nil, err
	}

	// Calculate distance
	distance := gf.haversineDistance(
		gf.selfLocation.Latitude,
		gf.selfLocation.Longitude,
		location.Latitude,
		location.Longitude,
	)

	// Estimate latency (very rough approximation)
	// Light travels about 200km per millisecond in fiber, but routing and processing adds overhead
	latency := int(distance/100) + 10 // +10ms base latency

	// Determine if same ISP
	sameISP := gf.selfLocation.ISP == location.ISP

	// Calculate score (higher is better)
	// 1.0 = perfect score (0 distance, same ISP)
	// 0.0 = worst score (max preferredRadius, different ISP)
	distanceScore := 1.0 - math.Min(1.0, distance/gf.options.PreferredRadius)
	ispBonus := 0.0
	if sameISP && gf.options.PreferSameISP {
		ispBonus = 0.2 // 20% bonus for same ISP
	}

	// Final score
	score := (distanceScore * gf.options.DistanceWeight) +
		((1.0 - gf.options.DistanceWeight) * ispBonus)

	// If latency exceeds maximum, penalize the score
	if latency > gf.options.MaxLatency {
		penalty := float64(latency-gf.options.MaxLatency) / float64(gf.options.MaxLatency)
		score = score * (1.0 - math.Min(0.9, penalty)) // Max 90% penalty
	}

	return &GeoScore{
		PeerID:   p,
		Distance: distance,
		Latency:  latency,
		SameISP:  sameISP,
		Score:    score,
		Location: location,
	}, nil
}

// SortPeersByGeoScore sorts peers by their geographic optimization score
func (gf *GeoFilter) SortPeersByGeoScore(peers []peer.AddrInfo) ([]*GeoScore, error) {
	scores := make([]*GeoScore, 0, len(peers))

	// Calculate scores for all peers
	for _, p := range peers {
		score, err := gf.ScorePeer(p.ID, p.Addrs)
		if err != nil {
			// Skip peers we can't score instead of failing
			continue
		}
		scores = append(scores, score)
	}

	// Sort by score (highest first)
	sort := func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	}

	// Manual bubble sort for simplicity
	for i := 0; i < len(scores); i++ {
		for j := 0; j < len(scores)-i-1; j++ {
			if sort(j+1, j) {
				scores[j], scores[j+1] = scores[j+1], scores[j]
			}
		}
	}

	return scores, nil
}

// FilterPeersByGeoScore filters a peer list based on geographic scores
func (gf *GeoFilter) FilterPeersByGeoScore(peers []peer.AddrInfo, minScore float64) ([]peer.AddrInfo, error) {
	scores, err := gf.SortPeersByGeoScore(peers)
	if err != nil {
		return nil, err
	}

	// Filter peers with scores above the minimum
	filteredPeers := make([]peer.AddrInfo, 0)
	for _, score := range scores {
		if score.Score >= minScore {
			for _, p := range peers {
				if p.ID == score.PeerID {
					filteredPeers = append(filteredPeers, p)
					break
				}
			}
		}
	}

	return filteredPeers, nil
}

// GetBestNPeers returns the N best peers according to geographic optimization
func (gf *GeoFilter) GetBestNPeers(peers []peer.AddrInfo, n int) ([]peer.AddrInfo, error) {
	scores, err := gf.SortPeersByGeoScore(peers)
	if err != nil {
		return nil, err
	}

	// Take the top N peers
	count := int(math.Min(float64(n), float64(len(scores))))
	bestPeers := make([]peer.AddrInfo, 0, count)

	for i := 0; i < count; i++ {
		for _, p := range peers {
			if p.ID == scores[i].PeerID {
				bestPeers = append(bestPeers, p)
				break
			}
		}
	}

	return bestPeers, nil
}
