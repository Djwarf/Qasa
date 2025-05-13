package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
)

// DHTDiscoveryInterval is how often we re-publish our DHT records
const DHTDiscoveryInterval = time.Hour

// DHTServiceTag is the namespace used in DHT advertisements
const DHTServiceTag = "qasa-dht"

// DHTService represents the DHT-based peer discovery service
type DHTService struct {
	host      host.Host
	dht       *dht.IpfsDHT
	discovery *routing.RoutingDiscovery
	ctx       context.Context
	cancel    context.CancelFunc
	peers     chan peer.AddrInfo
	wg        sync.WaitGroup
}

// NewDHTService creates a new DHT-based discovery service
func NewDHTService(ctx context.Context, h host.Host, bootstrapPeers []multiaddr.Multiaddr) (*DHTService, error) {
	// Create a cancellable context
	ctx, cancel := context.WithCancel(ctx)

	// Create a channel for discovered peers
	peers := make(chan peer.AddrInfo)

	// Convert multiaddrs to peer.AddrInfo
	var bootstrapPeerInfos []peer.AddrInfo
	if len(bootstrapPeers) > 0 {
		bootstrapPeerInfos = make([]peer.AddrInfo, 0, len(bootstrapPeers))
		for _, addr := range bootstrapPeers {
			peerInfo, err := peer.AddrInfoFromP2pAddr(addr)
			if err != nil {
				fmt.Printf("Invalid bootstrap peer address: %s\n", err)
				continue
			}
			bootstrapPeerInfos = append(bootstrapPeerInfos, *peerInfo)
		}
	}

	// Configure and create the DHT
	opts := []dht.Option{
		dht.Mode(dht.ModeClient),
	}

	if len(bootstrapPeerInfos) > 0 {
		opts = append(opts, dht.BootstrapPeers(bootstrapPeerInfos...))
	}

	kadDHT, err := dht.New(ctx, h, opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	// Create the routing discovery service
	discovery := routing.NewRoutingDiscovery(kadDHT)

	return &DHTService{
		host:      h,
		dht:       kadDHT,
		discovery: discovery,
		ctx:       ctx,
		cancel:    cancel,
		peers:     peers,
	}, nil
}

// Start begins advertising and discovering peers via DHT
func (s *DHTService) Start() error {
	// Bootstrap the DHT
	if err := s.dht.Bootstrap(s.ctx); err != nil {
		return fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// Start advertising
	s.wg.Add(1)
	go s.advertise()

	// Start discovering
	s.wg.Add(1)
	go s.discoverPeers()

	return nil
}

// advertise periodically advertises our presence to the DHT
func (s *DHTService) advertise() {
	defer s.wg.Done()

	// Advertise initially
	s.advertiseOnce()

	// Then advertise periodically
	ticker := time.NewTicker(DHTDiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.advertiseOnce()
		case <-s.ctx.Done():
			return
		}
	}
}

// advertiseOnce performs a single advertisement to the DHT
func (s *DHTService) advertiseOnce() {
	_, err := s.discovery.Advertise(s.ctx, DHTServiceTag)
	if err != nil {
		fmt.Printf("Error advertising to DHT: %s\n", err)
		return
	}

	fmt.Printf("Successfully advertised as %s in the DHT\n", s.host.ID().String())
}

// discoverPeers continuously looks for peers in the DHT
func (s *DHTService) discoverPeers() {
	defer s.wg.Done()

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.findPeers()
		case <-s.ctx.Done():
			return
		}
	}
}

// findPeers performs a search for peers in the DHT
func (s *DHTService) findPeers() {
	fmt.Printf("Searching for peers via DHT...\n")

	// Find peers advertising the service
	peerChan, err := s.discovery.FindPeers(s.ctx, DHTServiceTag)
	if err != nil {
		fmt.Printf("Error finding peers: %s\n", err)
		return
	}

	// Process discovered peers
	go func() {
		for peer := range peerChan {
			// Skip self
			if peer.ID == s.host.ID() {
				continue
			}

			fmt.Printf("Discovered peer via DHT: %s\n", peer.ID.String())

			// Add the peer to our peerstore with a longer TTL
			s.host.Peerstore().AddAddrs(peer.ID, peer.Addrs, peerstore.PermanentAddrTTL)

			// Send the peer to the channel
			select {
			case s.peers <- peer:
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

// Stop halts the DHT discovery service
func (s *DHTService) Stop() error {
	s.cancel()
	s.wg.Wait()
	return s.dht.Close()
}

// DiscoveredPeers returns a channel of peers found via DHT
func (s *DHTService) DiscoveredPeers() <-chan peer.AddrInfo {
	return s.peers
} 