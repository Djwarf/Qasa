package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
)

// DiscoveryInterval is how often we re-publish our mDNS records.
const DiscoveryInterval = time.Hour

// DiscoveryServiceTag is used in our mDNS advertisements to discover other QaSa nodes.
const DiscoveryServiceTag = "qasa-network"

// MDNSService represents the mDNS discovery service
type MDNSService struct {
	host   host.Host
	mdns   mdns.Service
	peers  chan peer.AddrInfo
	ctx    context.Context
	cancel context.CancelFunc
}

// MDNSDiscoveryNotifee gets notified when we discover a new peer via mDNS discovery
type MDNSDiscoveryNotifee struct {
	PeerChan chan peer.AddrInfo
}

// HandlePeerFound is called when we find a new peer
func (n *MDNSDiscoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	n.PeerChan <- pi
}

// NewMDNSService creates a new mDNS discovery service and attaches it to the given libp2p Host
func NewMDNSService(ctx context.Context, h host.Host) (*MDNSService, error) {
	// Create a new PeerChan to receive discovered peers
	peers := make(chan peer.AddrInfo)

	// Create the notifee
	notifee := &MDNSDiscoveryNotifee{peers}

	// Create the mDNS service
	service := mdns.NewMdnsService(h, DiscoveryServiceTag, notifee)

	// Create a cancellable context
	ctx, cancel := context.WithCancel(ctx)

	return &MDNSService{
		host:   h,
		mdns:   service,
		peers:  peers,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start begins processing discovered peers and attempting to connect to them
func (s *MDNSService) Start() {
	go s.discoverPeers()
}

// discoverPeers handles the discovered peers and attempts to connect to them
func (s *MDNSService) discoverPeers() {
	for {
		select {
		case peer := <-s.peers:
			// Ignore our own peer ID
			if peer.ID == s.host.ID() {
				continue
			}
			
			fmt.Printf("Discovered peer: %s\n", peer.ID.String())
			
			// Try to connect to the discovered peer
			err := s.host.Connect(s.ctx, peer)
			if err != nil {
				fmt.Printf("Failed to connect to peer %s: %s\n", peer.ID.String(), err)
				continue
			}
			
			fmt.Printf("Connected to peer: %s\n", peer.ID.String())
			
		case <-s.ctx.Done():
			return
		}
	}
}

// Stop halts the discovery service
func (s *MDNSService) Stop() {
	s.cancel()
}

// DiscoveredPeers returns the channel with discovered peers
func (s *MDNSService) DiscoveredPeers() <-chan peer.AddrInfo {
	return s.peers
} 