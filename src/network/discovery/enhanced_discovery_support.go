package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// handleDiscoveryStream handles incoming discovery protocol streams
func (eds *EnhancedDiscoveryService) handleDiscoveryStream(stream network.Stream) {
	defer stream.Close()
	
	reader := bufio.NewReader(stream)
	writer := bufio.NewWriter(stream)
	
	// Read incoming peer info request
	data, err := reader.ReadBytes('\n')
	if err != nil {
		return
	}
	
	var request PeerInfoRequest
	if err := json.Unmarshal(data[:len(data)-1], &request); err != nil {
		return
	}
	
	// Prepare our peer info response
	response := eds.preparePeerInfoResponse()
	
	// Send response
	responseData, err := json.Marshal(response)
	if err != nil {
		return
	}
	
	writer.Write(responseData)
	writer.WriteByte('\n')
	writer.Flush()
}

// PeerInfoRequest represents a request for peer information
type PeerInfoRequest struct {
	Type      string    `json:"type"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}

// exchangePeerInfo exchanges peer information over a stream
func (eds *EnhancedDiscoveryService) exchangePeerInfo(stream network.Stream) (*PeerInfo, error) {
	reader := bufio.NewReader(stream)
	writer := bufio.NewWriter(stream)
	
	// Send our peer info request
	request := PeerInfoRequest{
		Type:      "peer_info",
		RequestID: fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
	}
	
	requestData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	writer.Write(requestData)
	writer.WriteByte('\n')
	if err := writer.Flush(); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	
	// Read response
	data, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	var peerInfo PeerInfo
	if err := json.Unmarshal(data[:len(data)-1], &peerInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &peerInfo, nil
}

// preparePeerInfoResponse prepares our peer information for sharing
func (eds *EnhancedDiscoveryService) preparePeerInfoResponse() *PeerInfo {
	capabilities := []string{"secure-messaging", "file-transfer"}
	encryptionAlgos := []string{"kyber", "dilithium", "aes-256-gcm"}
	
	// Check if we support post-quantum
	postQuantum := true
	for _, algo := range encryptionAlgos {
		if algo == "kyber" || algo == "dilithium" {
			postQuantum = true
			break
		}
	}
	
	// Get our identifiers
	var identifiers []string
	if eds.identifier != nil {
		// Add any registered identifiers
		// This would be implementation specific
	}
	
	metadata := map[string]string{
		"version":    "1.0.0",
		"node_type":  "qasa-node",
		"build_time": time.Now().Format(time.RFC3339),
	}
	
	return &PeerInfo{
		Capabilities:         capabilities,
		EncryptionAlgorithms: encryptionAlgos,
		PostQuantumSupport:   postQuantum,
		Identifiers:          identifiers,
		Metadata:             metadata,
		Version:              "1.0.0",
		Timestamp:            time.Now(),
	}
}

// peerMaintenanceLoop performs periodic maintenance on peer metrics
func (eds *EnhancedDiscoveryService) peerMaintenanceLoop() {
	ticker := time.NewTicker(60 * time.Second) // Run every minute
	defer ticker.Stop()
	
	for {
		select {
		case <-eds.ctx.Done():
			return
		case <-ticker.C:
			eds.performPeerMaintenance()
		}
	}
}

// performPeerMaintenance cleans up stale peers and updates metrics
func (eds *EnhancedDiscoveryService) performPeerMaintenance() {
	eds.mu.Lock()
	defer eds.mu.Unlock()
	
	now := time.Now()
	staleThreshold := 5 * time.Minute
	
	// Find stale peers
	var stalePeers []peer.ID
	for peerID, metrics := range eds.peerMetrics {
		if now.Sub(metrics.LastSeen) > staleThreshold {
			stalePeers = append(stalePeers, peerID)
		}
	}
	
	// Mark stale peers as offline
	for _, peerID := range stalePeers {
		if metrics, exists := eds.peerMetrics[peerID]; exists {
			if metrics.Online {
				metrics.Online = false
				if eds.onPeerLost != nil {
					go eds.onPeerLost(peerID)
				}
			}
		}
	}
	
	// Clean up very old peers (older than 1 hour and offline)
	cleanupThreshold := 1 * time.Hour
	for peerID, metrics := range eds.peerMetrics {
		if !metrics.Online && now.Sub(metrics.LastSeen) > cleanupThreshold {
			delete(eds.peerMetrics, peerID)
		}
	}
	
	// Enforce max peers limit
	if len(eds.peerMetrics) > eds.config.MaxPeers {
		eds.enforceMaxPeersLimit()
	}
}

// enforceMaxPeersLimit removes least valuable peers when over limit
func (eds *EnhancedDiscoveryService) enforceMaxPeersLimit() {
	// Convert to slice for sorting
	type peerWithScore struct {
		id    peer.ID
		score float64
	}
	
	var peers []peerWithScore
	for peerID, metrics := range eds.peerMetrics {
		score := eds.calculateCompositeScore(metrics)
		peers = append(peers, peerWithScore{id: peerID, score: score})
	}
	
	// Sort by score (lowest first)
	for i := 0; i < len(peers)-1; i++ {
		for j := i + 1; j < len(peers); j++ {
			if peers[i].score > peers[j].score {
				peers[i], peers[j] = peers[j], peers[i]
			}
		}
	}
	
	// Remove lowest scoring peers
	toRemove := len(peers) - eds.config.MaxPeers
	for i := 0; i < toRemove; i++ {
		delete(eds.peerMetrics, peers[i].id)
	}
}

// reputationSyncLoop periodically syncs reputation data with trusted peers
func (eds *EnhancedDiscoveryService) reputationSyncLoop() {
	if !eds.config.EnableReputationSync {
		return
	}
	
	ticker := time.NewTicker(10 * time.Minute) // Sync every 10 minutes
	defer ticker.Stop()
	
	for {
		select {
		case <-eds.ctx.Done():
			return
		case <-ticker.C:
			eds.performReputationSync()
		}
	}
}

// performReputationSync syncs reputation data with trusted peers
func (eds *EnhancedDiscoveryService) performReputationSync() {
	eds.mu.RLock()
	trustedPeers := eds.getTrustedPeers()
	eds.mu.RUnlock()
	
	if len(trustedPeers) == 0 {
		return
	}
	
	// Select a few trusted peers to sync with
	maxSync := 3
	if len(trustedPeers) < maxSync {
		maxSync = len(trustedPeers)
	}
	
	for i := 0; i < maxSync; i++ {
		go eds.syncReputationWithPeer(trustedPeers[i])
	}
}

// getTrustedPeers returns peers with high trust levels
func (eds *EnhancedDiscoveryService) getTrustedPeers() []peer.ID {
	var trusted []peer.ID
	
	for peerID, metrics := range eds.peerMetrics {
		if metrics.TrustLevel >= TrustHigh && metrics.Online {
			trusted = append(trusted, peerID)
		}
	}
	
	return trusted
}

// syncReputationWithPeer syncs reputation data with a specific peer
func (eds *EnhancedDiscoveryService) syncReputationWithPeer(peerID peer.ID) {
	ctx, cancel := context.WithTimeout(eds.ctx, 30*time.Second)
	defer cancel()
	
	// This would implement a reputation sync protocol
	// For now, we'll just log the attempt
	_ = ctx // TODO: Use context when implementing actual sync protocol
	fmt.Printf("Syncing reputation with peer %s\n", peerID.String()[:8])
}

// GetPeerMetrics returns metrics for a specific peer
func (eds *EnhancedDiscoveryService) GetPeerMetrics(peerID peer.ID) (*PeerMetrics, bool) {
	eds.mu.RLock()
	defer eds.mu.RUnlock()
	
	metrics, exists := eds.peerMetrics[peerID]
	if !exists {
		return nil, false
	}
	
	// Return a copy to prevent external modification
	metricsCopy := *metrics
	return &metricsCopy, true
}

// GetAllPeerMetrics returns all peer metrics
func (eds *EnhancedDiscoveryService) GetAllPeerMetrics() map[peer.ID]*PeerMetrics {
	eds.mu.RLock()
	defer eds.mu.RUnlock()
	
	// Return copies to prevent external modification
	result := make(map[peer.ID]*PeerMetrics)
	for peerID, metrics := range eds.peerMetrics {
		metricsCopy := *metrics
		result[peerID] = &metricsCopy
	}
	
	return result
}

// UpdatePeerTrustLevel manually updates a peer's trust level
func (eds *EnhancedDiscoveryService) UpdatePeerTrustLevel(peerID peer.ID, trustLevel TrustLevel) error {
	eds.mu.Lock()
	defer eds.mu.Unlock()
	
	metrics, exists := eds.peerMetrics[peerID]
	if !exists {
		return fmt.Errorf("peer not found: %s", peerID.String())
	}
	
	oldTrustLevel := metrics.TrustLevel
	metrics.TrustLevel = trustLevel
	
	// Adjust reputation based on trust level change
	switch trustLevel {
	case TrustVerified:
		metrics.Reputation = math.Min(MaxReputation, metrics.Reputation+20)
	case TrustHigh:
		metrics.Reputation = math.Min(MaxReputation, metrics.Reputation+10)
	case TrustMedium:
		if oldTrustLevel > TrustMedium {
			metrics.Reputation = math.Max(MinReputation, metrics.Reputation-10)
		}
	case TrustLow:
		metrics.Reputation = math.Max(MinReputation, metrics.Reputation-20)
	case TrustUnknown:
		metrics.Reputation = DefaultReputation
	}
	
	return nil
}

// GetDiscoveryStats returns statistics about the discovery service
func (eds *EnhancedDiscoveryService) GetDiscoveryStats() *DiscoveryStats {
	eds.mu.RLock()
	defer eds.mu.RUnlock()
	
	stats := &DiscoveryStats{
		TotalPeers:     len(eds.peerMetrics),
		OnlinePeers:    0,
		TrustedPeers:   0,
		LastDiscovery:  eds.lastDiscovery,
		DiscoveryCount: eds.discoveryCount,
		Running:        eds.running,
	}
	
	// Count online and trusted peers
	for _, metrics := range eds.peerMetrics {
		if metrics.Online {
			stats.OnlinePeers++
		}
		if metrics.TrustLevel >= TrustHigh {
			stats.TrustedPeers++
		}
	}
	
	return stats
}

// DiscoveryStats contains statistics about the discovery service
type DiscoveryStats struct {
	TotalPeers     int       `json:"total_peers"`
	OnlinePeers    int       `json:"online_peers"`
	TrustedPeers   int       `json:"trusted_peers"`
	LastDiscovery  time.Time `json:"last_discovery"`
	DiscoveryCount int64     `json:"discovery_count"`
	Running        bool      `json:"running"`
}

// String methods for TrustLevel
func (tl TrustLevel) String() string {
	switch tl {
	case TrustUnknown:
		return "unknown"
	case TrustLow:
		return "low"
	case TrustMedium:
		return "medium"
	case TrustHigh:
		return "high"
	case TrustVerified:
		return "verified"
	default:
		return "unknown"
	}
}

// MarshalJSON for TrustLevel
func (tl TrustLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(tl.String())
}

// UnmarshalJSON for TrustLevel
func (tl *TrustLevel) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	
	switch s {
	case "unknown":
		*tl = TrustUnknown
	case "low":
		*tl = TrustLow
	case "medium":
		*tl = TrustMedium
	case "high":
		*tl = TrustHigh
	case "verified":
		*tl = TrustVerified
	default:
		*tl = TrustUnknown
	}
	
	return nil
} 