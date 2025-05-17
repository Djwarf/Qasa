package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/qasa/network/discovery"
	"github.com/qasa/network/encryption"
	"github.com/qasa/network/libp2p"
	"github.com/qasa/network/message"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for development
	},
}

type WebServer struct {
	node                *libp2p.Node
	chatProtocol        *message.ChatProtocol
	wsClients           map[*websocket.Conn]bool
	wsMutex             sync.Mutex
	identifierDiscovery *discovery.IdentifierDiscoveryService
}

func NewWebServer(node *libp2p.Node, chatProtocol *message.ChatProtocol, identifierDiscovery *discovery.IdentifierDiscoveryService) *WebServer {
	ws := &WebServer{
		node:                node,
		chatProtocol:        chatProtocol,
		wsClients:           make(map[*websocket.Conn]bool),
		identifierDiscovery: identifierDiscovery,
	}

	// Register a message receiver
	go ws.monitorMessagesAndPeers()

	return ws
}

// monitorMessagesAndPeers is a background goroutine that watches for new messages and peers
func (ws *WebServer) monitorMessagesAndPeers() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var lastPeerCount int
	lastPeerList := make([]peer.ID, 0)

	for {
		select {
		case <-ticker.C:
			// Get current peers
			currentPeers := ws.node.Peers()

			// Check if peer list has changed
			if len(currentPeers) != lastPeerCount || !peerListsEqual(currentPeers, lastPeerList) {
				// Update our tracking
				lastPeerCount = len(currentPeers)
				lastPeerList = make([]peer.ID, len(currentPeers))
				copy(lastPeerList, currentPeers)

				// Broadcast updated peer list
				ws.BroadcastContactList()
			}
		}
	}
}

// Helper function to compare peer lists
func peerListsEqual(a, b []peer.ID) bool {
	if len(a) != len(b) {
		return false
	}

	// Create map of peer IDs in b
	bMap := make(map[string]bool)
	for _, peer := range b {
		bMap[peer.String()] = true
	}

	// Check if all peers in a are also in b
	for _, peer := range a {
		if !bMap[peer.String()] {
			return false
		}
	}

	return true
}

func (ws *WebServer) Start(port int) error {
	// Set up monitoring for messages by integrating with chat protocol
	// This is a workaround since we can't directly hook into the message handling
	// Every few seconds we'll check for new peers and messages

	// Serve static files
	http.Handle("/", http.FileServer(http.Dir(filepath.Join("src", "web"))))

	// WebSocket endpoint
	http.HandleFunc("/ws", ws.handleWebSocket)

	// API endpoints
	http.HandleFunc("/api/status", ws.handleStatusAPI)
	http.HandleFunc("/api/peers", ws.handlePeersAPI)
	http.HandleFunc("/api/search", ws.handleSearchAPI)

	// Start the server
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Web interface available at http://localhost%s\n", addr)
	return http.ListenAndServe(addr, nil)
}

func (ws *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("Failed to upgrade connection: %v\n", err)
		return
	}

	// Register the client
	ws.wsMutex.Lock()
	ws.wsClients[conn] = true
	ws.wsMutex.Unlock()

	// Send initial peer ID
	peerID := ws.node.ID().String()
	ws.sendToClient(conn, "peer_id", map[string]string{
		"peer_id": peerID,
	})

	// Send initial contact list
	ws.sendContactList(conn)

	// Send node status
	status := ws.getNodeStatus()
	ws.sendToClient(conn, "node_status", status)

	// Handle incoming messages
	go ws.handleClientMessages(conn)
}

func (ws *WebServer) handleClientMessages(conn *websocket.Conn) {
	defer func() {
		conn.Close()
		ws.wsMutex.Lock()
		delete(ws.wsClients, conn)
		ws.wsMutex.Unlock()
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}

		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "message":
			var data struct {
				To      string `json:"to"`
				Content string `json:"content"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Send the message through the chat protocol
			if err := ws.chatProtocol.SendMessageToPeer(data.To, data.Content); err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to send message: %v", err),
				})
			} else {
				// Also send the message back to the client for display
				ws.sendToClient(conn, "message_sent", map[string]interface{}{
					"to":        data.To,
					"content":   data.Content,
					"timestamp": time.Now().Format(time.RFC3339),
				})
			}

		case "connect":
			var data struct {
				PeerAddr string `json:"peer_addr"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Connect to the peer
			if err := ws.node.Connect(context.Background(), data.PeerAddr); err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to connect to peer: %v", err),
				})
				continue
			}

			// Extract peer ID from the address
			peerIDStr := extractPeerID(data.PeerAddr)
			if peerIDStr == "" {
				ws.sendToClient(conn, "error", map[string]string{
					"message": "Invalid peer address",
				})
				continue
			}

			// Notify the client
			ws.sendToClient(conn, "peer_connected", map[string]string{
				"peer_id": peerIDStr,
			})

			// Update contact list for all clients
			ws.BroadcastContactList()

		case "search":
			var data struct {
				Query string `json:"query"`
				Type  string `json:"type"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Perform search based on query type
			var results []map[string]interface{}
			var err error

			switch data.Type {
			case "name":
				results, err = ws.searchPeersByName(data.Query)
			case "key":
				results, err = ws.searchPeersByKey(data.Query)
			default:
				// Default to regular peer search
				results, err = ws.searchPeers(data.Query)
			}

			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Search failed: %v", err),
				})
				continue
			}

			// Send results to client
			ws.sendToClient(conn, "search_results", map[string]interface{}{
				"query":   data.Query,
				"type":    data.Type,
				"results": results,
			})

		case "set_identifier":
			var data struct {
				Username string `json:"username"`
				KeyID    string `json:"key_id"`
				Metadata string `json:"metadata"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Set username for this node
			var metadata []byte
			if data.Metadata != "" {
				metadata = []byte(data.Metadata)
			}

			err := ws.identifierDiscovery.SetSelfIdentifier(data.Username, data.KeyID, metadata)
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to set identifier: %v", err),
				})
				continue
			}

			ws.sendToClient(conn, "identifier_set", map[string]string{
				"username": data.Username,
			})

		case "key_exchange":
			var data struct {
				PeerID    string `json:"peer_id"`
				Algorithm string `json:"algorithm"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Decode the peer ID
			targetPeer, err := peer.Decode(data.PeerID)
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Invalid peer ID: %v", err),
				})
				continue
			}

			// Perform key exchange - use the existing command
			err = ws.performKeyExchange(targetPeer, data.Algorithm)
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to perform key exchange: %v", err),
				})
				continue
			}

			ws.sendToClient(conn, "key_exchange_completed", map[string]interface{}{
				"peer_id":   data.PeerID,
				"algorithm": data.Algorithm,
			})

		case "authenticate":
			var data struct {
				PeerID string `json:"peer_id"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Decode the peer ID
			targetPeer, err := peer.Decode(data.PeerID)
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Invalid peer ID: %v", err),
				})
				continue
			}

			// Authenticate the peer
			if _, err := ws.node.AuthenticatePeer(targetPeer); err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to authenticate peer: %v", err),
				})
				continue
			}

			ws.sendToClient(conn, "peer_authenticated", map[string]string{
				"peer_id": data.PeerID,
			})

			// Update contact list for all clients
			ws.BroadcastContactList()

		case "settings":
			var data struct {
				Port         int  `json:"port"`
				MDNS         bool `json:"mdns"`
				DHT          bool `json:"dht"`
				RequireAuth  bool `json:"require_auth"`
				OfflineQueue bool `json:"offline_queue"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Update node settings
			if data.MDNS {
				if err := ws.node.EnableMDNS(); err != nil {
					ws.sendToClient(conn, "error", map[string]string{
						"message": fmt.Sprintf("Failed to enable mDNS: %v", err),
					})
					continue
				}
			} else {
				ws.node.DisableMDNS()
			}

			if data.DHT {
				if err := ws.node.EnableDHT(); err != nil {
					ws.sendToClient(conn, "error", map[string]string{
						"message": fmt.Sprintf("Failed to enable DHT: %v", err),
					})
					continue
				}
			} else {
				ws.node.DisableDHT()
			}

			// Update chat protocol settings
			if data.OfflineQueue {
				if err := ws.chatProtocol.EnableOfflineQueue(); err != nil {
					ws.sendToClient(conn, "error", map[string]string{
						"message": fmt.Sprintf("Failed to enable offline queue: %v", err),
					})
					continue
				}
			} else {
				ws.chatProtocol.DisableOfflineQueue()
			}

			// Send updated status to the client
			ws.sendToClient(conn, "settings_updated", ws.getNodeStatus())

		case "get_keys":
			// Get key store
			keyStore, err := encryption.NewKeyStore(ws.node.GetConfigDir())
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to access key store: %v", err),
				})
				continue
			}

			// List keys
			keys := keyStore.ListKeys()

			ws.sendToClient(conn, "keys", map[string]interface{}{
				"keys": keys,
			})

		case "generate_keys":
			var data struct {
				Algorithm string `json:"algorithm"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Get key store
			keyStore, err := encryption.NewKeyStore(ws.node.GetConfigDir())
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to access key store: %v", err),
				})
				continue
			}

			// Generate new key
			key, err := keyStore.GenerateKey(data.Algorithm)
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to generate key: %v", err),
				})
				continue
			}

			ws.sendToClient(conn, "key_generated", map[string]interface{}{
				"key": key,
			})

		case "import_keys":
			var data struct {
				KeyData string `json:"data"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Get key store
			keyStore, err := encryption.NewKeyStore(ws.node.GetConfigDir())
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to access key store: %v", err),
				})
				continue
			}

			// Import key
			key, err := keyStore.ImportKey([]byte(data.KeyData))
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to import key: %v", err),
				})
				continue
			}

			ws.sendToClient(conn, "key_imported", map[string]interface{}{
				"key": key,
			})

		case "export_keys":
			var data struct {
				KeyID string `json:"key_id"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Get key store
			keyStore, err := encryption.NewKeyStore(ws.node.GetConfigDir())
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to access key store: %v", err),
				})
				continue
			}

			// Export key
			keyData, err := keyStore.ExportKey(data.KeyID)
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to export key: %v", err),
				})
				continue
			}

			ws.sendToClient(conn, "key_exported", map[string]interface{}{
				"key_id": data.KeyID,
				"data":   string(keyData),
			})

		case "delete_keys":
			var data struct {
				PeerID    string `json:"peer_id"`
				Algorithm string `json:"algorithm"`
			}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				continue
			}

			// Get key store
			keyStore, err := encryption.NewKeyStore(ws.node.GetConfigDir())
			if err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to access key store: %v", err),
				})
				continue
			}

			// Delete key
			if err := keyStore.DeleteKey(data.PeerID, data.Algorithm); err != nil {
				ws.sendToClient(conn, "error", map[string]string{
					"message": fmt.Sprintf("Failed to delete key: %v", err),
				})
				continue
			}

			ws.sendToClient(conn, "key_deleted", map[string]string{
				"peer_id":   data.PeerID,
				"algorithm": data.Algorithm,
			})
		}
	}
}

// Search for peers based on username
func (ws *WebServer) searchPeersByName(username string) ([]map[string]interface{}, error) {
	if ws.identifierDiscovery == nil {
		return nil, fmt.Errorf("identifier discovery service not available")
	}

	// Search for the username in the identifier discovery system
	records, err := ws.identifierDiscovery.FindUserByName(username)
	if err != nil {
		return nil, fmt.Errorf("failed to search by username: %v", err)
	}

	results := make([]map[string]interface{}, 0)
	for _, record := range records {
		// Try to parse peer ID
		peerID, err := peer.Decode(record.PeerID)
		if err != nil {
			continue
		}

		// Check if we're connected to this peer
		connected := false
		for _, connPeer := range ws.node.Peers() {
			if connPeer == peerID {
				connected = true
				break
			}
		}

		result := map[string]interface{}{
			"peer_id":       record.PeerID,
			"username":      record.Identifier,
			"connected":     connected,
			"key_id":        record.KeyID,
			"authenticated": ws.node.IsPeerAuthenticated(peerID),
			"last_updated":  record.Timestamp.Format(time.RFC3339),
		}

		// Add metadata if available
		if len(record.Metadata) > 0 {
			result["metadata"] = string(record.Metadata)
		}

		results = append(results, result)
	}

	return results, nil
}

// Search for peers based on key ID
func (ws *WebServer) searchPeersByKey(keyID string) ([]map[string]interface{}, error) {
	if ws.identifierDiscovery == nil {
		return nil, fmt.Errorf("identifier discovery service not available")
	}

	// Search for the key ID in the identifier discovery system
	records, err := ws.identifierDiscovery.FindUserByKeyID(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to search by key ID: %v", err)
	}

	results := make([]map[string]interface{}, 0)
	for _, record := range records {
		// Try to parse peer ID
		peerID, err := peer.Decode(record.PeerID)
		if err != nil {
			continue
		}

		// Check if we're connected to this peer
		connected := false
		for _, connPeer := range ws.node.Peers() {
			if connPeer == peerID {
				connected = true
				break
			}
		}

		result := map[string]interface{}{
			"peer_id":       record.PeerID,
			"key_id":        record.KeyID,
			"connected":     connected,
			"authenticated": ws.node.IsPeerAuthenticated(peerID),
			"last_updated":  record.Timestamp.Format(time.RFC3339),
		}

		// Add username if this record has one
		if record.Type == "username" {
			result["username"] = record.Identifier
		}

		// Add metadata if available
		if len(record.Metadata) > 0 {
			result["metadata"] = string(record.Metadata)
		}

		results = append(results, result)
	}

	return results, nil
}

// Search for peers based on ID or other criteria
func (ws *WebServer) searchPeers(query string) ([]map[string]interface{}, error) {
	// Initialize DHT if not already enabled
	isEnabled := false
	if !isEnabled {
		if err := ws.node.EnableDHT(); err != nil {
			return nil, fmt.Errorf("failed to enable DHT for search: %v", err)
		}
	}

	// Get current peers
	currentPeers := ws.node.Peers()
	results := make([]map[string]interface{}, 0)

	// First check if any current peers match
	for _, peer := range currentPeers {
		peerStr := peer.String()
		if strings.Contains(strings.ToLower(peerStr), strings.ToLower(query)) {
			results = append(results, map[string]interface{}{
				"peer_id":       peerStr,
				"authenticated": ws.node.IsPeerAuthenticated(peer),
				"connected":     true,
			})
		}
	}

	// If we have identifier discovery and didn't find anything, try to search by identifiers
	if len(results) == 0 && ws.identifierDiscovery != nil {
		// Try by username
		nameResults, err := ws.searchPeersByName(query)
		if err == nil {
			results = append(results, nameResults...)
		}

		// Try by key
		keyResults, err := ws.searchPeersByKey(query)
		if err == nil {
			results = append(results, keyResults...)
		}
	}

	return results, nil
}

// Helper function to perform key exchange using the message protocol
func (ws *WebServer) performKeyExchange(peerID peer.ID, algorithm string) error {
	// Get key store for key pair generation
	keyStore, err := encryption.NewKeyStore(ws.node.GetConfigDir())
	if err != nil {
		return fmt.Errorf("failed to access key store: %v", err)
	}

	// Generate a key pair if it doesn't exist
	_, err = keyStore.GenerateKey(algorithm)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %v", err)
	}

	// We'll use the message protocol to exchange public keys
	// This is a simplification - in a real implementation, we would need a proper key exchange protocol
	keyExchangeMsg := fmt.Sprintf("KEY_EXCHANGE_REQUEST:%s", algorithm)
	if err := ws.chatProtocol.SendMessageToPeer(peerID.String(), keyExchangeMsg); err != nil {
		return fmt.Errorf("failed to send key exchange message: %v", err)
	}

	return nil
}

func (ws *WebServer) sendToClient(conn *websocket.Conn, msgType string, data interface{}) {
	message := struct {
		Type string      `json:"type"`
		Data interface{} `json:"data"`
	}{
		Type: msgType,
		Data: data,
	}

	if err := conn.WriteJSON(message); err != nil {
		fmt.Printf("Failed to send message to client: %v\n", err)
	}
}

func (ws *WebServer) sendContactList(conn *websocket.Conn) {
	peers := ws.node.Peers()
	contacts := make([]map[string]interface{}, len(peers))

	for i, peer := range peers {
		contacts[i] = map[string]interface{}{
			"peer_id":         peer.String(),
			"online":          true,
			"authenticated":   ws.node.IsPeerAuthenticated(peer),
			"queued_messages": ws.chatProtocol.GetOfflineQueuedMessageCount(peer),
		}
	}

	ws.sendToClient(conn, "contact_list", map[string]interface{}{
		"contacts": contacts,
	})
}

func (ws *WebServer) BroadcastMessage(msgType string, data interface{}) {
	ws.wsMutex.Lock()
	defer ws.wsMutex.Unlock()

	for conn := range ws.wsClients {
		ws.sendToClient(conn, msgType, data)
	}
}

func (ws *WebServer) BroadcastContactList() {
	peers := ws.node.Peers()
	contacts := make([]map[string]interface{}, len(peers))

	for i, peer := range peers {
		contacts[i] = map[string]interface{}{
			"peer_id":         peer.String(),
			"online":          true,
			"authenticated":   ws.node.IsPeerAuthenticated(peer),
			"queued_messages": ws.chatProtocol.GetOfflineQueuedMessageCount(peer),
		}
	}

	ws.BroadcastMessage("contact_list", map[string]interface{}{
		"contacts": contacts,
	})
}

// Handle API endpoint for search
func (ws *WebServer) handleSearchAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get search query from URL parameter
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Missing query parameter", http.StatusBadRequest)
		return
	}

	// Get search type from URL parameter
	searchType := r.URL.Query().Get("type")

	// Perform search based on type
	var results []map[string]interface{}
	var err error

	switch searchType {
	case "name":
		results, err = ws.searchPeersByName(query)
	case "key":
		results, err = ws.searchPeersByKey(query)
	default:
		results, err = ws.searchPeers(query)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Search failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Return results
	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":   query,
		"type":    searchType,
		"results": results,
	})
}

func (ws *WebServer) getNodeStatus() map[string]interface{} {
	// Get bootstrap nodes
	bootstrapNodes, err := ws.node.GetBootstrapNodes()
	bootstrapCount := 0
	if err == nil {
		bootstrapCount = len(bootstrapNodes)
	}

	return map[string]interface{}{
		"peer_id":             ws.node.ID().String(),
		"listening_addresses": ws.node.Addrs(),
		"connected_peers":     len(ws.node.Peers()),
		"bootstrap_nodes":     bootstrapCount,
		"authenticated_peers": len(ws.node.GetAuthenticatedPeers()),
	}
}

func (ws *WebServer) handleStatusAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ws.getNodeStatus())
}

func (ws *WebServer) handlePeersAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	peers := ws.node.Peers()
	peerInfos := make([]map[string]interface{}, len(peers))

	for i, peer := range peers {
		peerInfos[i] = map[string]interface{}{
			"peer_id":         peer.String(),
			"authenticated":   ws.node.IsPeerAuthenticated(peer),
			"queued_messages": ws.chatProtocol.GetOfflineQueuedMessageCount(peer),
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"peers": peerInfos,
	})
}
