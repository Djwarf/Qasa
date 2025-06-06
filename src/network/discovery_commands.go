package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/qasa/network/discovery"
)

// handleDiscoverCommand triggers a discovery scan
func handleDiscoverCommand(enhancedDiscovery *discovery.EnhancedDiscoveryService) {
	if enhancedDiscovery == nil {
		fmt.Println("Enhanced discovery service not available")
		return
	}

	fmt.Println("🔍 Starting discovery scan...")
	// The discovery service runs continuously, so this just shows current status
	stats := enhancedDiscovery.GetDiscoveryStats()
	fmt.Printf("Discovery service is %s\n", func() string {
		if stats.Running {
			return "running"
		}
		return "stopped"
	}())
	fmt.Printf("Last discovery: %s\n", stats.LastDiscovery.Format("15:04:05"))
	fmt.Printf("Total discoveries: %d\n", stats.DiscoveryCount)
}

// handleDiscoveryStatsCommand shows discovery statistics
func handleDiscoveryStatsCommand(enhancedDiscovery *discovery.EnhancedDiscoveryService) {
	if enhancedDiscovery == nil {
		fmt.Println("Enhanced discovery service not available")
		return
	}

	stats := enhancedDiscovery.GetDiscoveryStats()
	
	fmt.Println("\n📊 Discovery Statistics")
	fmt.Println("========================")
	fmt.Printf("Service Status:    %s\n", func() string {
		if stats.Running {
			return "🟢 Running"
		}
		return "🔴 Stopped"
	}())
	fmt.Printf("Total Peers:       %d\n", stats.TotalPeers)
	fmt.Printf("Online Peers:      %d\n", stats.OnlinePeers)
	fmt.Printf("Trusted Peers:     %d\n", stats.TrustedPeers)
	fmt.Printf("Last Discovery:    %s\n", stats.LastDiscovery.Format("2006-01-02 15:04:05"))
	fmt.Printf("Discovery Count:   %d\n", stats.DiscoveryCount)

	if stats.TotalPeers > 0 {
		onlinePercent := float64(stats.OnlinePeers) / float64(stats.TotalPeers) * 100
		trustedPercent := float64(stats.TrustedPeers) / float64(stats.TotalPeers) * 100
		fmt.Printf("Online Rate:       %.1f%%\n", onlinePercent)
		fmt.Printf("Trust Rate:        %.1f%%\n", trustedPercent)
	}
}

// handleBestPeersCommand shows the best peers based on composite score
func handleBestPeersCommand(tokens []string, enhancedDiscovery *discovery.EnhancedDiscoveryService) {
	if enhancedDiscovery == nil {
		fmt.Println("Enhanced discovery service not available")
		return
	}

	limit := 10 // default limit
	if len(tokens) > 1 {
		if l, err := strconv.Atoi(tokens[1]); err == nil && l > 0 {
			limit = l
		}
	}

	bestPeers := enhancedDiscovery.GetBestPeers(limit)
	
	if len(bestPeers) == 0 {
		fmt.Println("No peers found")
		return
	}

	fmt.Printf("\n🌟 Top %d Peers\n", len(bestPeers))
	fmt.Println("=====================================")
	fmt.Printf("%-4s %-12s %-8s %-8s %-8s %-12s\n", "#", "Peer ID", "Rep", "Latency", "Trust", "Status")
	fmt.Println("-------------------------------------")

	for i, peer := range bestPeers {
		peerIDShort := shortPeerID(peer.PeerID.String())
		reputation := fmt.Sprintf("%.1f", peer.Reputation)
		latency := "N/A"
		if peer.Latency > 0 {
			latency = fmt.Sprintf("%dms", peer.Latency.Milliseconds())
		}
		
		trustLevel := peer.TrustLevel.String()
		status := "🔴"
		if peer.Online {
			status = "🟢"
		}
		
		fmt.Printf("%-4d %-12s %-8s %-8s %-8s %-12s\n", 
			i+1, peerIDShort, reputation, latency, trustLevel, status)
		
		// Show identifiers if available
		if len(peer.Identifiers) > 0 {
			fmt.Printf("     Identifiers: %s\n", strings.Join(peer.Identifiers, ", "))
		}
		
		// Show capabilities if available
		if len(peer.Capabilities) > 0 {
			fmt.Printf("     Capabilities: %s\n", strings.Join(peer.Capabilities, ", "))
		}
		
		// Show post-quantum support
		if peer.PostQuantum {
			fmt.Printf("     🔐 Post-Quantum Support\n")
		}
		
		fmt.Println()
	}
}

// handleDiscoverySearchCommand searches for peers matching criteria
func handleDiscoverySearchCommand(tokens []string, enhancedDiscovery *discovery.EnhancedDiscoveryService) {
	if enhancedDiscovery == nil {
		fmt.Println("Enhanced discovery service not available")
		return
	}

	if len(tokens) < 2 {
		fmt.Println("Usage: disc-search <identifier>")
		return
	}

	query := &discovery.PeerSearchQuery{
		Identifier: tokens[1],
		Limit:      20,
	}

	results := enhancedDiscovery.SearchPeers(query)
	
	if len(results) == 0 {
		fmt.Printf("No peers found matching '%s'\n", tokens[1])
		return
	}

	fmt.Printf("\n🔎 Search Results for '%s'\n", tokens[1])
	fmt.Println("================================")
	
	for i, peer := range results {
		peerIDShort := shortPeerID(peer.PeerID.String())
		status := "🔴 Offline"
		if peer.Online {
			status = "🟢 Online"
		}
		
		fmt.Printf("%d. %s (%s)\n", i+1, peerIDShort, status)
		fmt.Printf("   Reputation: %.1f/100\n", peer.Reputation)
		fmt.Printf("   Trust Level: %s\n", peer.TrustLevel.String())
		
		if peer.Latency > 0 {
			fmt.Printf("   Latency: %dms\n", peer.Latency.Milliseconds())
		}
		
		if len(peer.Identifiers) > 0 {
			fmt.Printf("   Identifiers: %s\n", strings.Join(peer.Identifiers, ", "))
		}
		
		if len(peer.Capabilities) > 0 {
			fmt.Printf("   Capabilities: %s\n", strings.Join(peer.Capabilities, ", "))
		}
		
		if peer.PostQuantum {
			fmt.Printf("   🔐 Post-Quantum Support\n")
		}
		
		fmt.Println()
	}
}

// handlePeerTrustCommand updates a peer's trust level
func handlePeerTrustCommand(tokens []string, enhancedDiscovery *discovery.EnhancedDiscoveryService) {
	if enhancedDiscovery == nil {
		fmt.Println("Enhanced discovery service not available")
		return
	}

	if len(tokens) < 3 {
		fmt.Println("Usage: disc-trust <peer_id> <trust_level>")
		fmt.Println("Trust levels: unknown, low, medium, high, verified")
		return
	}

	peerIDStr := tokens[1]
	trustLevelStr := tokens[2]

	// Parse peer ID
	peerID, err := peer.Decode(peerIDStr)
	if err != nil {
		fmt.Printf("Invalid peer ID: %s\n", err)
		return
	}

	// Parse trust level
	var trustLevel discovery.TrustLevel
	switch strings.ToLower(trustLevelStr) {
	case "unknown":
		trustLevel = discovery.TrustUnknown
	case "low":
		trustLevel = discovery.TrustLow
	case "medium":
		trustLevel = discovery.TrustMedium
	case "high":
		trustLevel = discovery.TrustHigh
	case "verified":
		trustLevel = discovery.TrustVerified
	default:
		fmt.Printf("Invalid trust level: %s\n", trustLevelStr)
		fmt.Println("Valid levels: unknown, low, medium, high, verified")
		return
	}

	// Update trust level
	if err := enhancedDiscovery.UpdatePeerTrustLevel(peerID, trustLevel); err != nil {
		fmt.Printf("Failed to update trust level: %s\n", err)
		return
	}

	fmt.Printf("✅ Updated trust level for peer %s to %s\n", 
		shortPeerID(peerIDStr), trustLevel.String())
}

// handleExportPeerMetricsCommand exports peer metrics to a file
func handleExportPeerMetricsCommand(enhancedDiscovery *discovery.EnhancedDiscoveryService) {
	if enhancedDiscovery == nil {
		fmt.Println("Enhanced discovery service not available")
		return
	}

	allMetrics := enhancedDiscovery.GetAllPeerMetrics()
	
	if len(allMetrics) == 0 {
		fmt.Println("No peer metrics to export")
		return
	}

	// Prepare export data
	exportData := struct {
		Timestamp    time.Time                                 `json:"timestamp"`
		TotalPeers   int                                       `json:"total_peers"`
		PeerMetrics  map[string]*discovery.PeerMetrics         `json:"peer_metrics"`
		Stats        *discovery.DiscoveryStats                 `json:"discovery_stats"`
	}{
		Timestamp:   time.Now(),
		TotalPeers:  len(allMetrics),
		PeerMetrics: make(map[string]*discovery.PeerMetrics),
		Stats:       enhancedDiscovery.GetDiscoveryStats(),
	}

	// Convert peer.ID keys to strings for JSON serialization
	for peerID, metrics := range allMetrics {
		exportData.PeerMetrics[peerID.String()] = metrics
	}

	// Generate filename
	filename := fmt.Sprintf("qasa-peer-metrics-%s.json", time.Now().Format("20060102-150405"))

	// Marshal to JSON
	data, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal data: %s\n", err)
		return
	}

	// Write to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("Failed to write file: %s\n", err)
		return
	}

	fmt.Printf("✅ Exported %d peer metrics to %s\n", len(allMetrics), filename)
	fmt.Printf("File size: %.1f KB\n", float64(len(data))/1024.0)
} 