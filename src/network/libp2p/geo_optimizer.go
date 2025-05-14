package libp2p

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/qasa/network/discovery"
)

// GeoOptimizerOptions contains configuration for geographic peer optimization
type GeoOptimizerOptions struct {
	// Enable geographic peer optimization
	Enabled bool

	// Options for the geographic filter
	FilterOptions *discovery.GeoFilterOptions

	// Maximum number of connections to maintain
	MaxConnections int

	// Minimum acceptable geo score (0-1)
	MinAcceptableScore float64

	// How often to perform optimization
	OptimizeInterval time.Duration
}

// DefaultGeoOptimizerOptions returns default options for geographic optimizer
func DefaultGeoOptimizerOptions() *GeoOptimizerOptions {
	return &GeoOptimizerOptions{
		Enabled:            true,
		FilterOptions:      discovery.DefaultGeoFilterOptions(),
		MaxConnections:     50,
		MinAcceptableScore: 0.3, // At least 30% score
		OptimizeInterval:   15 * time.Minute,
	}
}

// GeoOptimizer handles geographic optimization of peer connections
type GeoOptimizer struct {
	node      *Node
	options   *GeoOptimizerOptions
	geoFilter *discovery.GeoFilter
	ctx       context.Context
	cancel    context.CancelFunc
	mutex     sync.RWMutex
	running   bool
}

// NewGeoOptimizer creates a new geographic connection optimizer
func NewGeoOptimizer(node *Node, options *GeoOptimizerOptions) (*GeoOptimizer, error) {
	if options == nil {
		options = DefaultGeoOptimizerOptions()
	}

	// Create the geographic filter
	geoFilter, err := discovery.NewGeoFilter(options.FilterOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create geographic filter: %w", err)
	}

	ctx, cancel := context.WithCancel(node.ctx)

	return &GeoOptimizer{
		node:      node,
		options:   options,
		geoFilter: geoFilter,
		ctx:       ctx,
		cancel:    cancel,
		running:   false,
	}, nil
}

// Start begins the geographic optimization process
func (g *GeoOptimizer) Start() {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if g.running {
		return
	}

	g.running = true

	// Start the optimization loop
	go g.optimizationLoop()

	fmt.Println("Geographic peer optimization started")
}

// Stop stops the geographic optimization process
func (g *GeoOptimizer) Stop() {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if !g.running {
		return
	}

	g.cancel()
	g.running = false

	fmt.Println("Geographic peer optimization stopped")
}

// optimizationLoop periodically performs geographic optimization of connections
func (g *GeoOptimizer) optimizationLoop() {
	ticker := time.NewTicker(g.options.OptimizeInterval)
	defer ticker.Stop()

	// Do an initial optimization
	g.optimizeConnections()

	for {
		select {
		case <-ticker.C:
			g.optimizeConnections()
		case <-g.ctx.Done():
			return
		}
	}
}

// optimizeConnections performs one round of connection optimization
func (g *GeoOptimizer) optimizeConnections() {
	// Get current peers
	peers := g.node.Peers()
	if len(peers) == 0 {
		return
	}

	// Convert to AddrInfo for scoring
	peerInfos := make([]peer.AddrInfo, 0, len(peers))
	for _, p := range peers {
		addrs := g.node.host.Peerstore().Addrs(p)
		peerInfos = append(peerInfos, peer.AddrInfo{
			ID:    p,
			Addrs: addrs,
		})
	}

	// Score all peers
	scores, err := g.geoFilter.SortPeersByGeoScore(peerInfos)
	if err != nil {
		fmt.Printf("Error scoring peers: %s\n", err)
		return
	}

	// Nothing to optimize if we have fewer than max connections
	if len(peers) <= g.options.MaxConnections {
		return
	}

	// Sort scores by value (already done by SortPeersByGeoScore)
	// Now identify peers to disconnect - the ones with lowest scores
	// that exceed our max connection count
	toDisconnect := make([]peer.ID, 0)

	// Start from the end (lowest scores) and work backwards
	for i := len(scores) - 1; i >= 0 && len(peers)-len(toDisconnect) > g.options.MaxConnections; i-- {
		score := scores[i]

		// Don't disconnect peers with good scores
		if score.Score >= g.options.MinAcceptableScore {
			break
		}

		toDisconnect = append(toDisconnect, score.PeerID)
	}

	// Log what we're doing
	if len(toDisconnect) > 0 {
		fmt.Printf("Optimizing connections: disconnecting %d low-scoring peers\n", len(toDisconnect))

		// Disconnect low-scoring peers
		for _, p := range toDisconnect {
			fmt.Printf("Disconnecting geographically distant peer: %s\n", p)
			g.node.host.Network().ClosePeer(p)
		}
	}
}

// ScorePeer calculates a geographic score for a peer
func (g *GeoOptimizer) ScorePeer(peerID peer.ID) (float64, error) {
	addrs := g.node.host.Peerstore().Addrs(peerID)
	if len(addrs) == 0 {
		return 0, fmt.Errorf("no addresses for peer %s", peerID)
	}

	score, err := g.geoFilter.ScorePeer(peerID, addrs)
	if err != nil {
		return 0, err
	}

	return score.Score, nil
}

// GetPeerLocation gets the geographic location of a peer
func (g *GeoOptimizer) GetPeerLocation(peerID peer.ID) (*discovery.GeoLocation, error) {
	addrs := g.node.host.Peerstore().Addrs(peerID)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses for peer %s", peerID)
	}

	return g.geoFilter.GetPeerLocation(peerID, addrs)
}

// ShouldConnectToPeer determines if a new peer should be connected to based on its geo score
func (g *GeoOptimizer) ShouldConnectToPeer(peerID peer.ID, addrs []peer.AddrInfo) (bool, error) {
	// If we're under max connections, always allow
	currentPeers := g.node.Peers()
	if len(currentPeers) < g.options.MaxConnections {
		return true, nil
	}

	// Otherwise, score this peer
	score, err := g.ScorePeer(peerID)
	if err != nil {
		// If we can't score, default to allowing
		return true, nil
	}

	// If score is above minimum, allow
	if score >= g.options.MinAcceptableScore {
		return true, nil
	}

	// If score is too low, only connect if this peer is better than our worst current peer
	peerInfos := make([]peer.AddrInfo, 0, len(currentPeers))
	for _, p := range currentPeers {
		peerAddrs := g.node.host.Peerstore().Addrs(p)
		peerInfos = append(peerInfos, peer.AddrInfo{
			ID:    p,
			Addrs: peerAddrs,
		})
	}

	// Get scores for all peers
	scores, err := g.geoFilter.SortPeersByGeoScore(peerInfos)
	if err != nil {
		// If error, default to allowing
		return true, nil
	}

	// If we have fewer than max connections, allow
	if len(scores) == 0 {
		return true, nil
	}

	// Check if this peer has a better score than our worst peer
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score < scores[j].Score
	})

	// If new peer score is better than our worst peer, allow
	if score > scores[0].Score {
		return true, nil
	}

	// Otherwise reject
	return false, nil
}
