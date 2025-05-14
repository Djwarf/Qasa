package libp2p

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"

	"github.com/qasa/network/discovery"
	"github.com/qasa/network/reputation"
)

// AuthenticatedPeer represents a peer with authentication information
type AuthenticatedPeer struct {
	PeerID       peer.ID
	PubKey       crypto.PubKey
	AuthTime     time.Time
	IsAuthorised bool
	Metadata     map[string]string
}

// Node represents a libp2p node in the QaSa network
type Node struct {
	host            host.Host
	ctx             context.Context
	cancel          context.CancelFunc
	mdnsService     *discovery.MDNSService
	dhtService      *discovery.DHTService
	bootstrapList   *discovery.BootstrapNodeList
	authorisedPeers map[peer.ID]*AuthenticatedPeer // Track authenticated peers
	privKey         crypto.PrivKey                 // Store our private key for authentication
	repManager      *reputation.Manager            // Reputation management system
	geoOptimizer    *GeoOptimizer                  // Geographic peer optimization
	configDir       string                         // Configuration directory
}

// NodeConfig contains configuration options for the node
type NodeConfig struct {
	EnableMDNS bool
	EnableDHT  bool
	ListenPort int
	// Authentication options
	RequireAuth  bool
	TrustedPeers []peer.ID
	// Bootstrap options
	BootstrapNodes []string
	ConfigDir      string
	// Geographical optimization options
	EnableGeoOptimization bool
	GeoOptimizerOptions   *GeoOptimizerOptions
}

// DefaultNodeConfig returns a default configuration for the node
func DefaultNodeConfig() *NodeConfig {
	return &NodeConfig{
		EnableMDNS:            true,
		EnableDHT:             false,
		ListenPort:            0, // Use random port
		RequireAuth:           false,
		TrustedPeers:          []peer.ID{},
		BootstrapNodes:        []string{},
		ConfigDir:             ".qasa",
		EnableGeoOptimization: false, // Disabled by default
		GeoOptimizerOptions:   nil,   // Use defaults if enabled
	}
}

// NewNode creates and configures a new libp2p node
func NewNode(ctx context.Context) (*Node, error) {
	return NewNodeWithConfig(ctx, DefaultNodeConfig())
}

// NewNodeWithConfig creates a new libp2p node with the provided configuration
func NewNodeWithConfig(ctx context.Context, config *NodeConfig) (*Node, error) {
	// Create a cancellable context
	ctx, cancel := context.WithCancel(ctx)

	// Generate a new key pair for this node
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, -1, rand.Reader)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Construct the listen address
	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.ListenPort)

	// Set up the libp2p host with basic options
	opts := []libp2p.Option{
		libp2p.Identity(priv),                 // Use our private key
		libp2p.ListenAddrStrings(listenAddr),  // Listen on specified interfaces and port
		libp2p.Security(noise.ID, noise.New),  // Use the Noise security protocol
		libp2p.Transport(tcp.NewTCPTransport), // Use TCP transport
		libp2p.NATPortMap(),                   // Attempt to NAT map ports
		libp2p.EnableRelay(),                  // Enable relay client functionality
		// Do not enable auto relay without static relays
		// libp2p.EnableAutoRelay(),               // Automatically detect and use relays
		libp2p.EnableHolePunching(), // Enable hole punching for NAT traversal
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	node := &Node{
		host:            h,
		ctx:             ctx,
		cancel:          cancel,
		privKey:         priv,
		authorisedPeers: make(map[peer.ID]*AuthenticatedPeer),
		configDir:       config.ConfigDir,
	}

	// Add trusted peers to the authorised list
	for _, peerID := range config.TrustedPeers {
		node.authorisedPeers[peerID] = &AuthenticatedPeer{
			PeerID:       peerID,
			AuthTime:     time.Now(),
			IsAuthorised: true,
		}
	}

	// Set up mDNS discovery if enabled
	if config.EnableMDNS {
		mdnsService, err := discovery.NewMDNSService(ctx, h)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create mDNS discovery service: %w", err)
		}

		node.mdnsService = mdnsService
		mdnsService.Start()
	}

	// Initialize the bootstrap node list
	bootstrapList, err := discovery.NewBootstrapNodeList(config.ConfigDir)
	if err != nil {
		fmt.Printf("Warning: Failed to initialize bootstrap node list: %s\n", err)
	} else {
		node.bootstrapList = bootstrapList

		// Add provided bootstrap nodes
		for _, addr := range config.BootstrapNodes {
			if err := bootstrapList.AddNode(addr); err != nil {
				fmt.Printf("Warning: Invalid bootstrap node %s: %s\n", addr, err)
			}
		}
	}

	// Set up DHT discovery if enabled
	if config.EnableDHT && node.bootstrapList != nil {
		// Get bootstrap multiaddresses
		bootstrapAddrs, err := node.bootstrapList.GetNodes()
		if err != nil {
			fmt.Printf("Warning: Failed to get bootstrap nodes: %s\n", err)
			bootstrapAddrs = nil
		}

		// Create the DHT service
		dhtService, err := discovery.NewDHTService(ctx, h, bootstrapAddrs)
		if err != nil {
			fmt.Printf("Warning: Failed to create DHT discovery service: %s\n", err)
		} else {
			node.dhtService = dhtService

			// Start the DHT service
			if err := dhtService.Start(); err != nil {
				fmt.Printf("Warning: Failed to start DHT discovery service: %s\n", err)
			} else {
				// Start a goroutine to handle discovered peers
				go node.handleDHTDiscoveredPeers()
			}
		}
	}

	// Enable geographic optimization if requested
	if config.EnableGeoOptimization {
		if err := node.EnableGeoOptimization(config.GeoOptimizerOptions); err != nil {
			fmt.Printf("Warning: Failed to enable geographic peer optimization: %s\n", err)
		} else {
			fmt.Println("Geographic peer optimization enabled")
		}
	}

	return node, nil
}

// handleDHTDiscoveredPeers processes peers discovered via DHT
func (n *Node) handleDHTDiscoveredPeers() {
	if n.dhtService == nil {
		return
	}

	for peer := range n.dhtService.DiscoveredPeers() {
		// Skip if we're already connected
		if n.host.Network().Connectedness(peer.ID) == network.Connected {
			continue
		}

		// Try to connect to the peer
		ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		if err := n.host.Connect(ctx, peer); err != nil {
			fmt.Printf("Failed to connect to discovered peer %s: %s\n", peer.ID, err)
			cancel()
			continue
		}
		cancel()

		fmt.Printf("Connected to discovered peer: %s\n", peer.ID)
	}
}

// ID returns the node's peer ID
func (n *Node) ID() peer.ID {
	return n.host.ID()
}

// Host returns the underlying libp2p host
func (n *Node) Host() host.Host {
	return n.host
}

// Addrs returns the node's listen addresses
func (n *Node) Addrs() []string {
	var addrs []string
	for _, addr := range n.host.Addrs() {
		addrs = append(addrs, addr.String())
	}
	return addrs
}

// Connect attempts to connect to a peer at the given address
func (n *Node) Connect(ctx context.Context, addrStr string) error {
	// Parse the multiaddress
	addr, err := peer.AddrInfoFromString(addrStr)
	if err != nil {
		return fmt.Errorf("invalid peer address: %w", err)
	}

	// Set a timeout for the connection attempt
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Try to connect to the peer
	if err := n.host.Connect(ctx, *addr); err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}

	// If this is a bootstrap node, record the successful connection
	if n.bootstrapList != nil && addr.ID != n.ID() {
		if err := n.bootstrapList.RecordSuccess(addrStr); err != nil {
			// Just log the error, don't fail the connection
			fmt.Printf("Warning: Failed to record successful connection to bootstrap node: %s\n", err)
		}
	}

	return nil
}

// Peers returns a list of connected peers
func (n *Node) Peers() []peer.ID {
	return n.host.Network().Peers()
}

// AuthenticatePeer authenticates a peer and adds it to the trusted peers list
func (n *Node) AuthenticatePeer(peerID peer.ID) (*AuthenticatedPeer, error) {
	// Check if peer exists
	if n.host.Network().Connectedness(peerID) != network.Connected {
		return nil, fmt.Errorf("not connected to peer %s", peerID.String())
	}

	// Get the peer's public key
	pubKey, err := n.getPeerPublicKey(peerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer's public key: %w", err)
	}

	// Create the authenticated peer
	authedPeer := &AuthenticatedPeer{
		PeerID:       peerID,
		PubKey:       pubKey,
		AuthTime:     time.Now(),
		IsAuthorised: true,
		Metadata:     make(map[string]string),
	}

	// Store the authenticated peer
	n.authorisedPeers[peerID] = authedPeer

	return authedPeer, nil
}

// IsPeerAuthenticated checks if a peer is authenticated
func (n *Node) IsPeerAuthenticated(peerID peer.ID) bool {
	authedPeer, exists := n.authorisedPeers[peerID]
	return exists && authedPeer.IsAuthorised
}

// GetAuthenticatedPeers returns all authenticated peers
func (n *Node) GetAuthenticatedPeers() []*AuthenticatedPeer {
	peers := make([]*AuthenticatedPeer, 0, len(n.authorisedPeers))
	for _, peer := range n.authorisedPeers {
		if peer.IsAuthorised {
			peers = append(peers, peer)
		}
	}
	return peers
}

// RemoveAuthentication removes a peer from the trusted list
func (n *Node) RemoveAuthentication(peerID peer.ID) {
	delete(n.authorisedPeers, peerID)
}

// getPeerPublicKey retrieves the public key of a peer
func (n *Node) getPeerPublicKey(peerID peer.ID) (crypto.PubKey, error) {
	// Try to get it from the peer store first
	pubKey := n.host.Peerstore().PubKey(peerID)
	if pubKey != nil {
		return pubKey, nil
	}

	// If not available, it could be extracted from the peer ID
	return peerID.ExtractPublicKey()
}

// UpdatePeerMetadata adds or updates metadata for an authenticated peer
func (n *Node) UpdatePeerMetadata(peerID peer.ID, key, value string) error {
	peer, exists := n.authorisedPeers[peerID]
	if !exists || !peer.IsAuthorised {
		return fmt.Errorf("peer %s is not authenticated", peerID.String())
	}

	peer.Metadata[key] = value
	return nil
}

// AddBootstrapNode adds a node to the bootstrap list
func (n *Node) AddBootstrapNode(addr string) error {
	if n.bootstrapList == nil {
		return fmt.Errorf("bootstrap node list not initialized")
	}

	return n.bootstrapList.AddNode(addr)
}

// RemoveBootstrapNode removes a node from the bootstrap list
func (n *Node) RemoveBootstrapNode(addr string) error {
	if n.bootstrapList == nil {
		return fmt.Errorf("bootstrap node list not initialized")
	}

	return n.bootstrapList.RemoveNode(addr)
}

// GetBootstrapNodes returns the current list of bootstrap nodes
func (n *Node) GetBootstrapNodes() ([]string, error) {
	if n.bootstrapList == nil {
		return nil, fmt.Errorf("bootstrap node list not initialized")
	}

	addrs, err := n.bootstrapList.GetNodes()
	if err != nil {
		return nil, err
	}

	strAddrs := make([]string, len(addrs))
	for i, addr := range addrs {
		strAddrs[i] = addr.String()
	}

	return strAddrs, nil
}

// Close shuts down the node and releases resources
func (n *Node) Close() error {
	// Stop the discovery services if they're running
	if n.mdnsService != nil {
		n.mdnsService.Stop()
	}

	if n.dhtService != nil {
		if err := n.dhtService.Stop(); err != nil {
			fmt.Printf("Error stopping DHT service: %s\n", err)
		}
	}

	// Cancel the context to signal all goroutines to stop
	n.cancel()

	// Close the host
	return n.host.Close()
}

// EnableGeoOptimization enables geographic optimization of peer connections
func (n *Node) EnableGeoOptimization(options *GeoOptimizerOptions) error {
	if n.geoOptimizer != nil {
		// Already enabled
		return nil
	}

	optimizer, err := NewGeoOptimizer(n, options)
	if err != nil {
		return fmt.Errorf("failed to create geographic optimizer: %w", err)
	}

	n.geoOptimizer = optimizer
	optimizer.Start()

	return nil
}

// DisableGeoOptimization disables geographic optimization of peer connections
func (n *Node) DisableGeoOptimization() {
	if n.geoOptimizer == nil {
		return
	}

	n.geoOptimizer.Stop()
	n.geoOptimizer = nil
}

// IsGeoOptimizationEnabled checks if geographic optimization is enabled
func (n *Node) IsGeoOptimizationEnabled() bool {
	return n.geoOptimizer != nil && n.geoOptimizer.running
}

// GetPeerGeoScore gets the geographic score for a peer
func (n *Node) GetPeerGeoScore(peerID peer.ID) (float64, error) {
	if n.geoOptimizer == nil {
		return 0, fmt.Errorf("geographic optimization not enabled")
	}

	return n.geoOptimizer.ScorePeer(peerID)
}

// GetPeerLocation gets the geographic location of a peer
func (n *Node) GetPeerLocation(peerID peer.ID) (*discovery.GeoLocation, error) {
	if n.geoOptimizer == nil {
		return nil, fmt.Errorf("geographic optimization not enabled")
	}

	return n.geoOptimizer.GetPeerLocation(peerID)
}

// GetConfigDir returns the configuration directory path used by the node
func (n *Node) GetConfigDir() string {
	return n.configDir
}

// EnableMDNS enables the mDNS discovery service
func (n *Node) EnableMDNS() error {
	if n.mdnsService != nil {
		return nil // Already enabled
	}

	mdnsService, err := discovery.NewMDNSService(n.ctx, n.host)
	if err != nil {
		return fmt.Errorf("failed to create mDNS discovery service: %w", err)
	}

	n.mdnsService = mdnsService
	mdnsService.Start()
	return nil
}

// DisableMDNS disables the mDNS discovery service
func (n *Node) DisableMDNS() {
	if n.mdnsService != nil {
		n.mdnsService.Stop()
		n.mdnsService = nil
	}
}

// EnableDHT enables the DHT discovery service
func (n *Node) EnableDHT() error {
	if n.dhtService != nil {
		return nil // Already enabled
	}

	// Get bootstrap multiaddresses
	var bootstrapAddrs []multiaddr.Multiaddr
	if n.bootstrapList != nil {
		var err error
		bootstrapAddrs, err = n.bootstrapList.GetNodes()
		if err != nil {
			fmt.Printf("Warning: Failed to get bootstrap nodes: %s\n", err)
		}
	}

	// Create the DHT service
	dhtService, err := discovery.NewDHTService(n.ctx, n.host, bootstrapAddrs)
	if err != nil {
		return fmt.Errorf("failed to create DHT discovery service: %w", err)
	}

	n.dhtService = dhtService

	// Start the DHT service
	if err := dhtService.Start(); err != nil {
		n.dhtService = nil
		return fmt.Errorf("failed to start DHT discovery service: %w", err)
	}

	// Start a goroutine to handle discovered peers
	go n.handleDHTDiscoveredPeers()
	return nil
}

// DisableDHT disables the DHT discovery service
func (n *Node) DisableDHT() {
	if n.dhtService != nil {
		if err := n.dhtService.Stop(); err != nil {
			fmt.Printf("Error stopping DHT service: %s\n", err)
		}
		n.dhtService = nil
	}
}
