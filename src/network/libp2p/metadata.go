package libp2p

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const (
	// MetadataProtocolID is the ID of the metadata exchange protocol
	MetadataProtocolID = "/qasa/metadata/1.0.0"
	
	// MaxMetadataSize is the maximum size of metadata that can be exchanged
	MaxMetadataSize = 1024 * 10 // 10KB
)

// MetadataExchange handles the exchange of metadata between peers
type MetadataExchange struct {
	node             *Node
	ctx              context.Context
	mutex            sync.RWMutex
	localMetadata    map[string]string
	peerMetadata     map[peer.ID]map[string]string
	metadataHandlers map[string]MetadataHandler
}

// MetadataHandler is a function that handles a specific type of metadata
type MetadataHandler func(peerID peer.ID, value string) error

// MetadataMessage represents a metadata message exchanged between peers
type MetadataMessage struct {
	Type      string            `json:"type"`
	Timestamp int64             `json:"timestamp"`
	Data      map[string]string `json:"data"`
}

// NewMetadataExchange creates a new metadata exchange handler
func NewMetadataExchange(ctx context.Context, node *Node) *MetadataExchange {
	mx := &MetadataExchange{
		node:             node,
		ctx:              ctx,
		localMetadata:    make(map[string]string),
		peerMetadata:     make(map[peer.ID]map[string]string),
		metadataHandlers: make(map[string]MetadataHandler),
	}
	
	// Set the stream handler for the metadata protocol
	node.Host().SetStreamHandler(protocol.ID(MetadataProtocolID), mx.handleStream)
	
	// Set default metadata values
	mx.SetLocalMetadata("client", "qasa-go")
	mx.SetLocalMetadata("version", "0.1.0")
	mx.SetLocalMetadata("pq-algos", "kyber,dilithium")
	
	return mx
}

// SetLocalMetadata sets a local metadata value
func (mx *MetadataExchange) SetLocalMetadata(key, value string) {
	mx.mutex.Lock()
	defer mx.mutex.Unlock()
	
	mx.localMetadata[key] = value
}

// GetLocalMetadata gets a local metadata value
func (mx *MetadataExchange) GetLocalMetadata(key string) (string, bool) {
	mx.mutex.RLock()
	defer mx.mutex.RUnlock()
	
	value, exists := mx.localMetadata[key]
	return value, exists
}

// RegisterMetadataHandler registers a handler for a specific type of metadata
func (mx *MetadataExchange) RegisterMetadataHandler(metadataType string, handler MetadataHandler) {
	mx.mutex.Lock()
	defer mx.mutex.Unlock()
	
	mx.metadataHandlers[metadataType] = handler
}

// ExchangeMetadata sends metadata to a peer and receives their metadata
func (mx *MetadataExchange) ExchangeMetadata(peerID peer.ID) error {
	// Check if peer is connected
	if mx.node.Host().Network().Connectedness(peerID) != network.Connected {
		return fmt.Errorf("not connected to peer %s", peerID.String())
	}
	
	// Open a new stream
	ctx, cancel := context.WithTimeout(mx.ctx, 10*time.Second)
	defer cancel()
	
	stream, err := mx.node.Host().NewStream(ctx, peerID, protocol.ID(MetadataProtocolID))
	if err != nil {
		return fmt.Errorf("failed to open metadata stream: %w", err)
	}
	defer stream.Close()
	
	// Send our metadata
	if err := mx.sendMetadata(stream); err != nil {
		return fmt.Errorf("failed to send metadata: %w", err)
	}
	
	// Receive peer's metadata
	if err := mx.receiveMetadata(stream, peerID); err != nil {
		return fmt.Errorf("failed to receive metadata: %w", err)
	}
	
	return nil
}

// sendMetadata sends local metadata to a stream
func (mx *MetadataExchange) sendMetadata(stream network.Stream) error {
	mx.mutex.RLock()
	message := MetadataMessage{
		Type:      "metadata",
		Timestamp: time.Now().Unix(),
		Data:      mx.localMetadata,
	}
	mx.mutex.RUnlock()
	
	// Marshal to JSON
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	
	// Write to stream
	_, err = stream.Write(data)
	return err
}

// receiveMetadata receives metadata from a stream
func (mx *MetadataExchange) receiveMetadata(stream network.Stream, peerID peer.ID) error {
	// Read from stream
	data, err := io.ReadAll(io.LimitReader(stream, MaxMetadataSize))
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}
	
	// Unmarshal from JSON
	var message MetadataMessage
	if err := json.Unmarshal(data, &message); err != nil {
		return fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	
	// Store the peer's metadata
	mx.mutex.Lock()
	mx.peerMetadata[peerID] = message.Data
	mx.mutex.Unlock()
	
	// Call handlers for this metadata
	mx.mutex.RLock()
	defer mx.mutex.RUnlock()
	
	for key, value := range message.Data {
		if handler, ok := mx.metadataHandlers[key]; ok {
			if err := handler(peerID, value); err != nil {
				fmt.Printf("Error handling metadata '%s' from peer %s: %s\n", key, peerID, err)
			}
		}
	}
	
	return nil
}

// handleStream handles an incoming metadata stream
func (mx *MetadataExchange) handleStream(stream network.Stream) {
	peerID := stream.Conn().RemotePeer()
	
	// Receive peer's metadata
	if err := mx.receiveMetadata(stream, peerID); err != nil {
		fmt.Printf("Error receiving metadata from peer %s: %s\n", peerID, err)
		stream.Reset()
		return
	}
	
	// Send our metadata
	if err := mx.sendMetadata(stream); err != nil {
		fmt.Printf("Error sending metadata to peer %s: %s\n", peerID, err)
		stream.Reset()
		return
	}
	
	// Close the stream when done
	stream.Close()
}

// GetPeerMetadata gets a metadata value for a peer
func (mx *MetadataExchange) GetPeerMetadata(peerID peer.ID, key string) (string, bool) {
	mx.mutex.RLock()
	defer mx.mutex.RUnlock()
	
	metadata, exists := mx.peerMetadata[peerID]
	if !exists {
		return "", false
	}
	
	value, exists := metadata[key]
	return value, exists
}

// GetAllPeerMetadata gets all metadata for a peer
func (mx *MetadataExchange) GetAllPeerMetadata(peerID peer.ID) map[string]string {
	mx.mutex.RLock()
	defer mx.mutex.RUnlock()
	
	metadata, exists := mx.peerMetadata[peerID]
	if !exists {
		return nil
	}
	
	// Return a copy to avoid race conditions
	result := make(map[string]string, len(metadata))
	for k, v := range metadata {
		result[k] = v
	}
	
	return result
} 