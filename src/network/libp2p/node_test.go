package libp2p

import (
	"context"
	"testing"
	"time"
)

func TestNodeBasicFunctionality(t *testing.T) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Create two nodes
	node1, err := NewNode(ctx)
	if err != nil {
		t.Fatalf("Failed to create node1: %v", err)
	}
	defer node1.Close()
	
	node2, err := NewNode(ctx)
	if err != nil {
		t.Fatalf("Failed to create node2: %v", err)
	}
	defer node2.Close()
	
	// Get node addresses
	node1ID := node1.ID()
	
	// Connect node1 to node2
	node1Addr := node1.Addrs()[0] + "/p2p/" + node1ID.String()
	if err := node2.Connect(ctx, node1Addr); err != nil {
		t.Fatalf("Failed to connect node2 to node1: %v", err)
	}
	
	// Verify connection
	connected := false
	for _, peer := range node2.Peers() {
		if peer == node1ID {
			connected = true
			break
		}
	}
	
	if !connected {
		t.Fatalf("Node2 failed to connect to node1")
	}
	
	t.Logf("Node2 successfully connected to node1")
}

func TestPeerAuthentication(t *testing.T) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Create two nodes
	config := DefaultNodeConfig()
	config.RequireAuth = true
	
	node1, err := NewNodeWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create node1: %v", err)
	}
	defer node1.Close()
	
	node2, err := NewNodeWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("Failed to create node2: %v", err)
	}
	defer node2.Close()
	
	// Get node addresses
	node1ID := node1.ID()
	
	// Connect node1 to node2
	node1Addr := node1.Addrs()[0] + "/p2p/" + node1ID.String()
	if err := node2.Connect(ctx, node1Addr); err != nil {
		t.Fatalf("Failed to connect node2 to node1: %v", err)
	}
	
	// Verify connection
	time.Sleep(100 * time.Millisecond) // Give time for connection to establish
	connected := false
	for _, peer := range node2.Peers() {
		if peer == node1ID {
			connected = true
			break
		}
	}
	
	if !connected {
		t.Fatalf("Node2 failed to connect to node1")
	}
	
	// Verify node1 is not authenticated
	if node2.IsPeerAuthenticated(node1ID) {
		t.Fatalf("Node1 should not be authenticated yet")
	}
	
	// Authenticate node1
	if _, err := node2.AuthenticatePeer(node1ID); err != nil {
		t.Fatalf("Failed to authenticate node1: %v", err)
	}
	
	// Verify node1 is now authenticated
	if !node2.IsPeerAuthenticated(node1ID) {
		t.Fatalf("Node1 should be authenticated")
	}
	
	t.Logf("Peer authentication successful")
}

func TestMetadataExchange(t *testing.T) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Create two nodes
	node1, err := NewNode(ctx)
	if err != nil {
		t.Fatalf("Failed to create node1: %v", err)
	}
	defer node1.Close()
	
	node2, err := NewNode(ctx)
	if err != nil {
		t.Fatalf("Failed to create node2: %v", err)
	}
	defer node2.Close()
	
	// Initialize metadata exchange for both nodes
	mx1 := NewMetadataExchange(ctx, node1)
	mx2 := NewMetadataExchange(ctx, node2)
	
	// Set test metadata
	mx1.SetLocalMetadata("test-key", "test-value-1")
	mx2.SetLocalMetadata("test-key", "test-value-2")
	
	// Get node addresses
	node1ID := node1.ID()
	
	// Connect node1 to node2
	node1Addr := node1.Addrs()[0] + "/p2p/" + node1ID.String()
	if err := node2.Connect(ctx, node1Addr); err != nil {
		t.Fatalf("Failed to connect node2 to node1: %v", err)
	}
	
	// Wait for connection to establish
	time.Sleep(100 * time.Millisecond)
	
	// Exchange metadata
	if err := mx2.ExchangeMetadata(node1ID); err != nil {
		t.Fatalf("Failed to exchange metadata: %v", err)
	}
	
	// Verify metadata was exchanged
	time.Sleep(100 * time.Millisecond) // Give time for exchange to complete
	
	value, exists := mx2.GetPeerMetadata(node1ID, "test-key")
	if !exists {
		t.Fatalf("Metadata key not found")
	}
	
	if value != "test-value-1" {
		t.Fatalf("Unexpected metadata value: got %s, want test-value-1", value)
	}
	
	t.Logf("Metadata exchange successful")
} 