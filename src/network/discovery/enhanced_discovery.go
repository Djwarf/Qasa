package discovery

import (
	"context"
	"fmt"
	"log"
	"math"
	"sort"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	// Discovery protocols
	EnhancedDiscoveryProtocol = "/qasa/discovery/enhanced/1.0.0"
	
	// Reputation constants
	MinReputation = 0.0
	MaxReputation = 100.0
	DefaultReputation = 50.0
	
	// Discovery intervals
	DefaultDiscoveryInterval = 30 * time.Second
	FastDiscoveryInterval = 5 * time.Second
	SlowDiscoveryInterval = 120 * time.Second
)

// PeerMetrics contains detailed metrics about a discovered peer
type PeerMetrics struct {
	PeerID           peer.ID           `json:"peer_id"`
	Identifiers      []string          `json:"identifiers"`
	LastSeen         time.Time         `json:"last_seen"`
	FirstSeen        time.Time         `json:"first_seen"`
	ResponseTime     time.Duration     `json:"response_time"`
	Reputation       float64           `json:"reputation"`
	ConnectionCount  int               `json:"connection_count"`
	SuccessfulConns  int               `json:"successful_connections"`
	FailedConns      int               `json:"failed_connections"`
	Proximity        float64           `json:"proximity"` // 0-1, closer to 1 is better
	Capabilities     []string          `json:"capabilities"`
	EncryptionAlgos  []string          `json:"encryption_algorithms"`
	PostQuantum      bool              `json:"post_quantum_support"`
	Latency          time.Duration     `json:"latency"`
	Bandwidth        float64           `json:"bandwidth_estimate"` // MB/s
	GeoLocation      *GeoLocation      `json:"geo_location,omitempty"`
	Addresses        []ma.Multiaddr    `json:"addresses"`
	Metadata         map[string]string `json:"metadata"`
	Tags             []string          `json:"tags"`
	Online           bool              `json:"online"`
	Authenticated    bool              `json:"authenticated"`
	TrustLevel       TrustLevel        `json:"trust_level"`
}

// TrustLevel represents the trust level of a peer
type TrustLevel int

const (
	TrustUnknown TrustLevel = iota
	TrustLow
	TrustMedium
	TrustHigh
	TrustVerified
)



// DiscoveryConfig contains configuration for the enhanced discovery service
type DiscoveryConfig struct {
	EnableMDNS           bool          `json:"enable_mdns"`
	EnableDHT            bool          `json:"enable_dht"`
	EnableIdentifier     bool          `json:"enable_identifier"`
	EnableGeoFiltering   bool          `json:"enable_geo_filtering"`
	EnableReputationSync bool          `json:"enable_reputation_sync"`
	DiscoveryInterval    time.Duration `json:"discovery_interval"`
	MaxPeers             int           `json:"max_peers"`
	MinReputation        float64       `json:"min_reputation"`
	ProximityWeight      float64       `json:"proximity_weight"`
	ReputationWeight     float64       `json:"reputation_weight"`
	LatencyWeight        float64       `json:"latency_weight"`
	AllowedCountries     []string      `json:"allowed_countries"`
	BlockedCountries     []string      `json:"blocked_countries"`
	RequirePostQuantum   bool          `json:"require_post_quantum"`
}

// EnhancedDiscoveryService provides advanced peer discovery with reputation and metrics
type EnhancedDiscoveryService struct {
	host            host.Host
	dht             *dht.IpfsDHT
	mdns            *MDNSService
	identifier      *IdentifierDiscoveryService
	geoFilter       *GeoFilter
	
	config          *DiscoveryConfig
	peerMetrics     map[peer.ID]*PeerMetrics
	discoveredPeers chan peer.AddrInfo
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	
	// Event handlers
	onPeerFound     func(*PeerMetrics)
	onPeerLost      func(peer.ID)
	onPeerUpdated   func(*PeerMetrics)
	
	// Internal state
	running         bool
	lastDiscovery   time.Time
	discoveryCount  int64
}

// NewEnhancedDiscoveryService creates a new enhanced discovery service
func NewEnhancedDiscoveryService(ctx context.Context, h host.Host, dht *dht.IpfsDHT, config *DiscoveryConfig) (*EnhancedDiscoveryService, error) {
	if config == nil {
		config = DefaultDiscoveryConfig()
	}
	
	ctx, cancel := context.WithCancel(ctx)
	
	service := &EnhancedDiscoveryService{
		host:            h,
		dht:             dht,
		config:          config,
		peerMetrics:     make(map[peer.ID]*PeerMetrics),
		discoveredPeers: make(chan peer.AddrInfo, 100),
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// Initialize sub-services
	if config.EnableMDNS {
		mdns, err := NewMDNSService(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("failed to create mDNS service: %w", err)
		}
		service.mdns = mdns
	}
	
	if config.EnableIdentifier && dht != nil {
		identifier, err := NewIdentifierDiscoveryService(ctx, h, dht, ".qasa")
		if err != nil {
			return nil, fmt.Errorf("failed to create identifier service: %w", err)
		}
		service.identifier = identifier
	}
	
	if config.EnableGeoFiltering {
		geoFilter, err := NewGeoFilter(DefaultGeoFilterOptions())
		if err != nil {
			// Log warning but continue without geo filtering
			log.Printf("Warning: could not initialize geo filter: %v", err)
		} else {
			service.geoFilter = geoFilter
		}
	}
	
	// Set up protocol handler
	h.SetStreamHandler(EnhancedDiscoveryProtocol, service.handleDiscoveryStream)
	
	return service, nil
}

// DefaultDiscoveryConfig returns a default configuration
func DefaultDiscoveryConfig() *DiscoveryConfig {
	return &DiscoveryConfig{
		EnableMDNS:           true,
		EnableDHT:            true,
		EnableIdentifier:     true,
		EnableGeoFiltering:   false,
		EnableReputationSync: true,
		DiscoveryInterval:    DefaultDiscoveryInterval,
		MaxPeers:             1000,
		MinReputation:        30.0,
		ProximityWeight:      0.3,
		ReputationWeight:     0.4,
		LatencyWeight:        0.3,
		RequirePostQuantum:   false,
	}
}

// Start begins the discovery service
func (eds *EnhancedDiscoveryService) Start() error {
	eds.mu.Lock()
	defer eds.mu.Unlock()
	
	if eds.running {
		return fmt.Errorf("discovery service already running")
	}
	
	// Start sub-services
	if eds.mdns != nil {
		eds.mdns.Start()
	}
	
	if eds.identifier != nil {
		if err := eds.identifier.Start(); err != nil {
			return fmt.Errorf("failed to start identifier service: %w", err)
		}
	}
	
	eds.running = true
	
	// Start discovery routines
	go eds.discoveryLoop()
	go eds.peerMaintenanceLoop()
	go eds.reputationSyncLoop()
	
	return nil
}

// Stop stops the discovery service
func (eds *EnhancedDiscoveryService) Stop() {
	eds.mu.Lock()
	defer eds.mu.Unlock()
	
	if !eds.running {
		return
	}
	
	eds.running = false
	eds.cancel()
	
	// Stop sub-services
	if eds.mdns != nil {
		eds.mdns.Stop()
	}
	
	if eds.identifier != nil {
		eds.identifier.Stop()
	}
	
	close(eds.discoveredPeers)
}

// discoveryLoop runs the main discovery process
func (eds *EnhancedDiscoveryService) discoveryLoop() {
	ticker := time.NewTicker(eds.config.DiscoveryInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-eds.ctx.Done():
			return
		case <-ticker.C:
			eds.performDiscovery()
		case peerInfo := <-eds.discoveredPeers:
			eds.handleDiscoveredPeer(peerInfo)
		}
	}
}

// performDiscovery executes a discovery round across all enabled methods
func (eds *EnhancedDiscoveryService) performDiscovery() {
	eds.mu.Lock()
	eds.lastDiscovery = time.Now()
	eds.discoveryCount++
	eds.mu.Unlock()
	
	// Collect peers from all discovery methods
	var allPeers []peer.AddrInfo
	
	// mDNS discovery
	if eds.mdns != nil {
		mdnsPeers := eds.collectMDNSPeers()
		allPeers = append(allPeers, mdnsPeers...)
	}
	
	// DHT discovery
	if eds.dht != nil {
		dhtPeers := eds.collectDHTPeers()
		allPeers = append(allPeers, dhtPeers...)
	}
	
	// Process discovered peers
	for _, peerInfo := range allPeers {
		eds.handleDiscoveredPeer(peerInfo)
	}
}

// collectMDNSPeers collects peers from mDNS
func (eds *EnhancedDiscoveryService) collectMDNSPeers() []peer.AddrInfo {
	if eds.mdns == nil {
		return nil
	}
	
	var peers []peer.AddrInfo
	peerChan := eds.mdns.DiscoveredPeers()
	
	// Collect peers with timeout
	timeout := time.After(2 * time.Second)
	for {
		select {
		case peer, ok := <-peerChan:
			if !ok {
				return peers
			}
			peers = append(peers, peer)
		case <-timeout:
			return peers
		}
	}
}

// collectDHTPeers collects peers from DHT
func (eds *EnhancedDiscoveryService) collectDHTPeers() []peer.AddrInfo {
	if eds.dht == nil {
		return nil
	}
	
	// Use DHT routing table
	var peers []peer.AddrInfo
	routingTable := eds.dht.RoutingTable()
	
	for _, peerID := range routingTable.ListPeers() {
		if peerID == eds.host.ID() {
			continue
		}
		
		addrs := eds.host.Peerstore().Addrs(peerID)
		if len(addrs) > 0 {
			peers = append(peers, peer.AddrInfo{
				ID:    peerID,
				Addrs: addrs,
			})
		}
	}
	
	return peers
}

// handleDiscoveredPeer processes a newly discovered peer
func (eds *EnhancedDiscoveryService) handleDiscoveredPeer(peerInfo peer.AddrInfo) {
	if peerInfo.ID == eds.host.ID() {
		return
	}
	
	eds.mu.Lock()
	defer eds.mu.Unlock()
	
	// Get or create peer metrics
	metrics, exists := eds.peerMetrics[peerInfo.ID]
	if !exists {
		metrics = &PeerMetrics{
			PeerID:      peerInfo.ID,
			FirstSeen:   time.Now(),
			Reputation:  DefaultReputation,
			Addresses:   peerInfo.Addrs,
			Metadata:    make(map[string]string),
			TrustLevel:  TrustUnknown,
		}
		eds.peerMetrics[peerInfo.ID] = metrics
	}
	
	// Update metrics
	metrics.LastSeen = time.Now()
	metrics.Addresses = peerInfo.Addrs
	metrics.Online = true
	
	// Perform peer assessment
	go eds.assessPeer(peerInfo.ID)
	
	// Notify handlers
	if eds.onPeerFound != nil && !exists {
		go eds.onPeerFound(metrics)
	} else if eds.onPeerUpdated != nil && exists {
		go eds.onPeerUpdated(metrics)
	}
}

// assessPeer performs detailed assessment of a peer
func (eds *EnhancedDiscoveryService) assessPeer(peerID peer.ID) {
	ctx, cancel := context.WithTimeout(eds.ctx, 10*time.Second)
	defer cancel()
	
	// Measure latency
	start := time.Now()
	stream, err := eds.host.NewStream(ctx, peerID, EnhancedDiscoveryProtocol)
	if err != nil {
		eds.updatePeerConnectionStatus(peerID, false)
		return
	}
	defer stream.Close()
	
	latency := time.Since(start)
	
	// Exchange peer information
	peerInfo, err := eds.exchangePeerInfo(stream)
	if err != nil {
		eds.updatePeerConnectionStatus(peerID, false)
		return
	}
	
	eds.updatePeerConnectionStatus(peerID, true)
	eds.updatePeerMetrics(peerID, latency, peerInfo)
}

// updatePeerConnectionStatus updates connection statistics
func (eds *EnhancedDiscoveryService) updatePeerConnectionStatus(peerID peer.ID, success bool) {
	eds.mu.Lock()
	defer eds.mu.Unlock()
	
	metrics, exists := eds.peerMetrics[peerID]
	if !exists {
		return
	}
	
	metrics.ConnectionCount++
	if success {
		metrics.SuccessfulConns++
	} else {
		metrics.FailedConns++
	}
	
	// Update reputation based on connection success rate
	successRate := float64(metrics.SuccessfulConns) / float64(metrics.ConnectionCount)
	metrics.Reputation = math.Min(MaxReputation, metrics.Reputation + (successRate-0.5)*10)
	metrics.Reputation = math.Max(MinReputation, metrics.Reputation)
}

// updatePeerMetrics updates detailed peer metrics
func (eds *EnhancedDiscoveryService) updatePeerMetrics(peerID peer.ID, latency time.Duration, info *PeerInfo) {
	eds.mu.Lock()
	defer eds.mu.Unlock()
	
	metrics, exists := eds.peerMetrics[peerID]
	if !exists {
		return
	}
	
	metrics.Latency = latency
	metrics.ResponseTime = latency
	
	if info != nil {
		metrics.Capabilities = info.Capabilities
		metrics.EncryptionAlgos = info.EncryptionAlgorithms
		metrics.PostQuantum = info.PostQuantumSupport
		metrics.Identifiers = info.Identifiers
		
		// Update metadata
		for k, v := range info.Metadata {
			metrics.Metadata[k] = v
		}
		
		// Calculate proximity based on various factors
		metrics.Proximity = eds.calculateProximity(metrics, info)
	}
}

// PeerInfo represents information exchanged between peers
type PeerInfo struct {
	Capabilities          []string          `json:"capabilities"`
	EncryptionAlgorithms []string          `json:"encryption_algorithms"`
	PostQuantumSupport   bool              `json:"post_quantum_support"`
	Identifiers          []string          `json:"identifiers"`
	Metadata             map[string]string `json:"metadata"`
	Version              string            `json:"version"`
	Timestamp            time.Time         `json:"timestamp"`
}

// calculateProximity calculates proximity score based on various factors
func (eds *EnhancedDiscoveryService) calculateProximity(metrics *PeerMetrics, info *PeerInfo) float64 {
	var score float64 = 0.5 // Base score
	
	// Factor in latency (lower is better)
	if metrics.Latency > 0 {
		latencyScore := math.Max(0, 1.0 - float64(metrics.Latency.Milliseconds())/1000.0)
		score += latencyScore * 0.3
	}
	
	// Factor in shared capabilities
	if len(info.Capabilities) > 0 {
		// Assume we have some preferred capabilities
		sharedCaps := 0
		for _, cap := range info.Capabilities {
			if cap == "post-quantum" || cap == "secure-messaging" {
				sharedCaps++
			}
		}
		score += float64(sharedCaps) * 0.1
	}
	
	// Factor in post-quantum support
	if info.PostQuantumSupport && eds.config.RequirePostQuantum {
		score += 0.2
	}
	
	return math.Min(1.0, math.Max(0.0, score))
}

// GetBestPeers returns the best peers based on scoring algorithm
func (eds *EnhancedDiscoveryService) GetBestPeers(limit int) []*PeerMetrics {
	eds.mu.RLock()
	defer eds.mu.RUnlock()
	
	var peers []*PeerMetrics
	for _, metrics := range eds.peerMetrics {
		if metrics.Online && metrics.Reputation >= eds.config.MinReputation {
			peers = append(peers, metrics)
		}
	}
	
	// Sort by composite score
	sort.Slice(peers, func(i, j int) bool {
		scoreI := eds.calculateCompositeScore(peers[i])
		scoreJ := eds.calculateCompositeScore(peers[j])
		return scoreI > scoreJ
	})
	
	if limit > 0 && len(peers) > limit {
		peers = peers[:limit]
	}
	
	return peers
}

// calculateCompositeScore calculates a composite score for peer ranking
func (eds *EnhancedDiscoveryService) calculateCompositeScore(metrics *PeerMetrics) float64 {
	proximityScore := metrics.Proximity * eds.config.ProximityWeight
	reputationScore := (metrics.Reputation / MaxReputation) * eds.config.ReputationWeight
	
	latencyScore := 0.0
	if metrics.Latency > 0 {
		latencyScore = math.Max(0, 1.0 - float64(metrics.Latency.Milliseconds())/1000.0) * eds.config.LatencyWeight
	}
	
	return proximityScore + reputationScore + latencyScore
}

// SearchPeers searches for peers matching specific criteria
func (eds *EnhancedDiscoveryService) SearchPeers(query *PeerSearchQuery) []*PeerMetrics {
	eds.mu.RLock()
	defer eds.mu.RUnlock()
	
	var results []*PeerMetrics
	
	for _, metrics := range eds.peerMetrics {
		if eds.matchesCriteria(metrics, query) {
			results = append(results, metrics)
		}
	}
	
	// Sort results
	sort.Slice(results, func(i, j int) bool {
		return eds.calculateCompositeScore(results[i]) > eds.calculateCompositeScore(results[j])
	})
	
	if query.Limit > 0 && len(results) > query.Limit {
		results = results[:query.Limit]
	}
	
	return results
}

// PeerSearchQuery defines search criteria for peers
type PeerSearchQuery struct {
	Identifier        string    `json:"identifier"`
	Capabilities      []string  `json:"capabilities"`
	MinReputation     float64   `json:"min_reputation"`
	MaxLatency        time.Duration `json:"max_latency"`
	RequirePostQuantum bool     `json:"require_post_quantum"`
	Countries         []string  `json:"countries"`
	Tags              []string  `json:"tags"`
	TrustLevel        TrustLevel `json:"trust_level"`
	Limit             int       `json:"limit"`
}

// matchesCriteria checks if a peer matches search criteria
func (eds *EnhancedDiscoveryService) matchesCriteria(metrics *PeerMetrics, query *PeerSearchQuery) bool {
	// Check identifier
	if query.Identifier != "" {
		found := false
		for _, ident := range metrics.Identifiers {
			if ident == query.Identifier {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check reputation
	if metrics.Reputation < query.MinReputation {
		return false
	}
	
	// Check latency
	if query.MaxLatency > 0 && metrics.Latency > query.MaxLatency {
		return false
	}
	
	// Check post-quantum requirement
	if query.RequirePostQuantum && !metrics.PostQuantum {
		return false
	}
	
	// Check trust level
	if query.TrustLevel > TrustUnknown && metrics.TrustLevel < query.TrustLevel {
		return false
	}
	
	// Check capabilities
	if len(query.Capabilities) > 0 {
		for _, reqCap := range query.Capabilities {
			found := false
			for _, peerCap := range metrics.Capabilities {
				if peerCap == reqCap {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	
	return true
}

// Event handler setters
func (eds *EnhancedDiscoveryService) OnPeerFound(handler func(*PeerMetrics)) {
	eds.onPeerFound = handler
}

func (eds *EnhancedDiscoveryService) OnPeerLost(handler func(peer.ID)) {
	eds.onPeerLost = handler
}

func (eds *EnhancedDiscoveryService) OnPeerUpdated(handler func(*PeerMetrics)) {
	eds.onPeerUpdated = handler
}

// Additional methods for peer maintenance and reputation sync will be implemented separately
// due to length constraints... 