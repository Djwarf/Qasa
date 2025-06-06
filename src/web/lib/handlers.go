package lib

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/qasa/common"
)

// Enhanced WebSocket message handling
func (ws *WebServer) handleClientMessage(session *ClientSession, messageType int, data []byte) {
	if messageType != websocket.TextMessage {
		return
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("Error parsing WebSocket message: %v", err)
		return
	}

	msgType, ok := msg["type"].(string)
	if !ok {
		log.Printf("Invalid message type")
		return
	}

	log.Printf("📨 Handling message type: %s", msgType)

	switch msgType {
	case "send_message":
		ws.handleSendMessage(session, msg["data"])
	case "create_group":
		ws.handleCreateGroup(session, msg["data"])
	case "key_exchange":
		ws.handleKeyExchange(session, msg["data"])
	case "search_peers":
		ws.handleSearchPeers(session, msg["data"])
	case "set_profile":
		ws.handleSetProfile(session, msg["data"])
	case "get_profile":
		ws.handleGetProfile(session, msg["data"])
	case "heartbeat":
		ws.handleHeartbeat(session)
	
	// Enhanced message types
	case "typing_indicator":
		ws.handleTypingIndicator(session, msg["data"])
	case "ping":
		ws.handlePing(session, msg["data"])
	case "update_status":
		ws.handleUpdateStatus(session, msg["data"])
	case "request_file_chunk":
		ws.handleRequestFileChunk(session, msg["data"])
	case "get_encryption_sessions":
		ws.handleGetEncryptionSessions(session)
	case "start_encryption_session":
		ws.handleStartEncryptionSession(session, msg["data"])
	case "end_encryption_session":
		ws.handleEndEncryptionSession(session, msg["data"])
	default:
		log.Printf("Unknown message type: %s", msgType)
	}
}

// Basic message sending
func (ws *WebServer) handleSendMessage(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	targetPeerID, ok := dataMap["peer_id"].(string)
	if !ok {
		return
	}
	
	content, ok := dataMap["content"].(string)
	if !ok {
		return
	}
	
	log.Printf("Sending message from %s to %s: %s", session.peerID, targetPeerID, content)
	
	// Basic message forwarding to target peer
	ws.wsMutex.RLock()
	for conn, clientSession := range ws.wsClients {
		if clientSession.peerID == targetPeerID {
			response := map[string]interface{}{
				"type": "message_received",
				"data": map[string]interface{}{
					"from":    session.peerID,
					"content": content,
					"time":    time.Now().Unix(),
				},
			}
			
			if err := conn.WriteJSON(response); err != nil {
				log.Printf("Error sending message: %v", err)
			}
			break
		}
	}
	ws.wsMutex.RUnlock()
}

// Basic group creation
func (ws *WebServer) handleCreateGroup(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	groupName, ok := dataMap["name"].(string)
	if !ok {
		return
	}
	
	groupID := fmt.Sprintf("group_%d", time.Now().UnixNano())
	
	group := &GroupChat{
		ID:          groupID,
		Name:        groupName,
		Admin:       session.peerID,
		Created:     time.Now(),
		Members:     make(map[string]*GroupMember),
		IsEncrypted: true,
	}
	
	// Add creator as admin
	group.Members[session.peerID] = &GroupMember{
		PeerID:      session.peerID,
		Role:        "admin",
		JoinedAt:    time.Now(),
		IsOnline:    true,
	}
	
	ws.groupChats[groupID] = group
	
	response := map[string]interface{}{
		"type": "group_created",
		"data": group,
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending group created: %v", err)
	}
}

// Basic key exchange
func (ws *WebServer) handleKeyExchange(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	targetPeerID, ok := dataMap["peer_id"].(string)
	if !ok {
		return
	}
	
	algorithm, ok := dataMap["algorithm"].(string)
	if !ok {
		algorithm = "kyber"
	}
	
	log.Printf("Initiating %s key exchange with %s", algorithm, targetPeerID)
	
	response := map[string]interface{}{
		"type": "key_exchange_initiated",
		"data": map[string]interface{}{
			"peer_id":   targetPeerID,
			"algorithm": algorithm,
		},
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending key exchange response: %v", err)
	}
}

// Basic peer search
func (ws *WebServer) handleSearchPeers(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	query, ok := dataMap["query"].(string)
	if !ok {
		return
	}
	
	// Simple peer search
	results := make([]map[string]interface{}, 0)
	
	if ws.enhancedDiscovery != nil {
		// Use enhanced discovery if available
		log.Printf("Searching for peers with query: %s", query)
	}
	
	response := map[string]interface{}{
		"type": "search_results",
		"data": map[string]interface{}{
			"query":   query,
			"results": results,
		},
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending search results: %v", err)
	}
}

// Basic profile handling
func (ws *WebServer) handleSetProfile(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	profile := &UserProfile{
		PeerID:      session.peerID,
		LastSeen:    time.Now(),
		IsOnline:    true,
		Preferences: make(map[string]interface{}),
	}
	
	if displayName, ok := dataMap["display_name"].(string); ok {
		profile.DisplayName = displayName
	}
	
	if status, ok := dataMap["status"].(string); ok {
		profile.Status = status
	}
	
	ws.userProfiles[session.peerID] = profile
	
	response := map[string]interface{}{
		"type": "profile_updated",
		"data": profile,
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending profile update: %v", err)
	}
}

func (ws *WebServer) handleGetProfile(session *ClientSession, data interface{}) {
	profile, exists := ws.userProfiles[session.peerID]
	if !exists {
		profile = &UserProfile{
			PeerID:      session.peerID,
			LastSeen:    time.Now(),
			IsOnline:    true,
			Preferences: make(map[string]interface{}),
		}
		ws.userProfiles[session.peerID] = profile
	}
	
	response := map[string]interface{}{
		"type": "profile",
		"data": profile,
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending profile: %v", err)
	}
}

// Enhanced typing indicator handler
func (ws *WebServer) handleTypingIndicator(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	targetPeerID, ok := dataMap["peer_id"].(string)
	if !ok {
		return
	}
	
	typing, ok := dataMap["typing"].(bool)
	if !ok {
		return
	}
	
	// Forward typing indicator to target peer
	ws.wsMutex.RLock()
	for conn, clientSession := range ws.wsClients {
		if clientSession.peerID == targetPeerID {
			response := map[string]interface{}{
				"type": "typing_indicator",
				"data": map[string]interface{}{
					"peer_id": session.peerID,
					"typing":  typing,
				},
			}
			
			if err := conn.WriteJSON(response); err != nil {
				log.Printf("Error sending typing indicator: %v", err)
			}
			break
		}
	}
	ws.wsMutex.RUnlock()
}

// Ping/Pong for connection quality monitoring
func (ws *WebServer) handlePing(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	timestamp, ok := dataMap["timestamp"].(float64)
	if !ok {
		return
	}
	
	// Send pong response
	response := map[string]interface{}{
		"type": "pong",
		"data": map[string]interface{}{
			"timestamp":   timestamp,
			"server_time": time.Now().UnixMilli(),
		},
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending pong: %v", err)
	}
}

// Enhanced status update handler
func (ws *WebServer) handleUpdateStatus(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	status, ok := dataMap["status"].(string)
	if !ok {
		return
	}
	
	// Update user profile status
	if profile, exists := ws.userProfiles[session.peerID]; exists {
		profile.Status = status
		profile.LastSeen = time.Now()
		profile.IsOnline = true
		
		// Broadcast status change to all connected clients
		ws.broadcastStatusChange(session.peerID, profile)
	}
}

// Broadcast status changes to all clients
func (ws *WebServer) broadcastStatusChange(peerID string, profile *UserProfile) {
	response := map[string]interface{}{
		"type": "user_status_changed",
		"data": map[string]interface{}{
			"peer_id":   peerID,
			"status":    profile.Status,
			"online":    profile.IsOnline,
			"last_seen": profile.LastSeen,
		},
	}
	
	ws.wsMutex.RLock()
	for conn, _ := range ws.wsClients {
		if err := conn.WriteJSON(response); err != nil {
			log.Printf("Error broadcasting status change: %v", err)
		}
	}
	ws.wsMutex.RUnlock()
}

// Enhanced file transfer with chunking
func (ws *WebServer) handleRequestFileChunk(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	transferID, ok := dataMap["transfer_id"].(string)
	if !ok {
		return
	}
	
	chunkIndex, ok := dataMap["chunk_index"].(float64)
	if !ok {
		return
	}
	
	transfer, exists := ws.fileTransfers[transferID]
	if !exists {
		return
	}
	
	// Read and send file chunk
	go ws.sendFileChunk(session, transfer, int(chunkIndex))
}

func (ws *WebServer) sendFileChunk(session *ClientSession, transfer *FileTransfer, chunkIndex int) {
	const chunkSize = 64 * 1024 // 64KB chunks
	
	file, err := os.Open(transfer.FilePath)
	if err != nil {
		log.Printf("Error opening file: %v", err)
		return
	}
	defer file.Close()
	
	// Seek to chunk position
	offset := int64(chunkIndex) * chunkSize
	if _, err := file.Seek(offset, 0); err != nil {
		log.Printf("Error seeking file: %v", err)
		return
	}
	
	// Read chunk
	chunk := make([]byte, chunkSize)
	bytesRead, err := file.Read(chunk)
	if err != nil && err != io.EOF {
		log.Printf("Error reading file chunk: %v", err)
		return
	}
	
	// Encode chunk data
	chunkData := base64.StdEncoding.EncodeToString(chunk[:bytesRead])
	
	// Calculate progress
	progress := float64(offset+int64(bytesRead)) / float64(transfer.FileSize) * 100
	
	response := map[string]interface{}{
		"type": "file_chunk",
		"data": map[string]interface{}{
			"transfer_id": transfer.ID,
			"chunk_index": chunkIndex,
			"chunk_data":  chunkData,
			"bytes_read":  bytesRead,
			"progress":    progress,
			"is_last":     bytesRead < chunkSize,
		},
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending file chunk: %v", err)
	}
	
	// Update transfer progress
	transfer.Progress = progress
	if progress >= 100 {
		transfer.Status = "completed"
		transfer.EndTime = time.Now()
	}
}

// Get encryption sessions
func (ws *WebServer) handleGetEncryptionSessions(session *ClientSession) {
	sessions := make([]*EncryptionSession, 0)
	
	for _, encSession := range ws.encryptionSessions {
		if encSession.PeerID == session.peerID {
			// Don't send session keys
			sessionCopy := *encSession
			sessionCopy.SessionKey = nil
			sessions = append(sessions, &sessionCopy)
		}
	}
	
	response := map[string]interface{}{
		"type": "encryption_sessions",
		"data": map[string]interface{}{
			"sessions": sessions,
		},
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending encryption sessions: %v", err)
	}
}

// Start encryption session
func (ws *WebServer) handleStartEncryptionSession(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	targetPeerID, ok := dataMap["target_peer_id"].(string)
	if !ok {
		return
	}
	
	algorithm, ok := dataMap["algorithm"].(string)
	if !ok {
		algorithm = "kyber" // Default to Kyber
	}
	
	// Generate session key
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		log.Printf("Error generating session key: %v", err)
		return
	}
	
	// Create encryption session
	sessionID := fmt.Sprintf("enc_%s_%s_%d", session.peerID, targetPeerID, time.Now().UnixNano())
	encSession := &EncryptionSession{
		PeerID:       targetPeerID,
		SessionKey:   sessionKey,
		Algorithm:    algorithm,
		KeyExchanged: false,
		LastUsed:     time.Now(),
		MessageCount: 0,
	}
	
	ws.encryptionSessions[sessionID] = encSession
	
	// Initiate key exchange with target peer
	if ws.node != nil {
		go func() {
			// Use the network layer for actual key exchange
			log.Printf("Starting %s key exchange with %s", algorithm, targetPeerID)
		}()
	}
	
	response := map[string]interface{}{
		"type": "encryption_session_started",
		"data": map[string]interface{}{
			"session_id":  sessionID,
			"target_peer": targetPeerID,
			"algorithm":   algorithm,
		},
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending encryption session started: %v", err)
	}
}

// End encryption session
func (ws *WebServer) handleEndEncryptionSession(session *ClientSession, data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}
	
	sessionID, ok := dataMap["session_id"].(string)
	if !ok {
		return
	}
	
	// Clean up session
	delete(ws.encryptionSessions, sessionID)
	
	response := map[string]interface{}{
		"type": "encryption_session_ended",
		"data": map[string]interface{}{
			"session_id": sessionID,
		},
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending encryption session ended: %v", err)
	}
}

// Enhanced heartbeat with additional status info
func (ws *WebServer) handleHeartbeat(session *ClientSession) {
	session.lastActivity = time.Now()
	
	// Update online status
	if profile, exists := ws.userProfiles[session.peerID]; exists {
		profile.LastSeen = time.Now()
		profile.IsOnline = true
	}
	
	peerCount := 0
	if ws.node != nil {
		peerCount = len(ws.node.Peers())
	}
	
	// Send back stats and status
	response := map[string]interface{}{
		"type": "heartbeat_ack",
		"data": map[string]interface{}{
			"server_time":     time.Now().Unix(),
			"active_sessions": len(ws.wsClients),
			"peer_count":      peerCount,
		},
	}
	
	if err := session.conn.WriteJSON(response); err != nil {
		log.Printf("Error sending heartbeat ack: %v", err)
	}
}

// Enhanced connection monitoring
func (ws *WebServer) updateOnlineStatus(currentPeers []peer.ID) {
	peerMap := make(map[string]bool)
	for _, p := range currentPeers {
		peerMap[p.String()] = true
	}
	
	// Update profiles with current online status
	for peerID, profile := range ws.userProfiles {
		wasOnline := profile.IsOnline
		profile.IsOnline = peerMap[peerID]
		
		// If status changed, broadcast update
		if wasOnline != profile.IsOnline {
			ws.broadcastStatusChange(peerID, profile)
		}
	}
}

// Helper function to check if peer lists are equal
func peerListsEqual(a, b []peer.ID) bool {
	return common.PeerListsEqual(a, b)
}

// Broadcast contact list update
func (ws *WebServer) BroadcastContactList() {
	contacts := make([]map[string]interface{}, 0)
	
	if ws.node != nil {
		for _, peerID := range ws.node.Peers() {
			contact := map[string]interface{}{
				"peer_id":    peerID.String(),
				"online":     true,
				"last_seen":  time.Now(),
			}
			
			if profile, exists := ws.userProfiles[peerID.String()]; exists {
				contact["display_name"] = profile.DisplayName
				contact["status"] = profile.Status
			}
			
			contacts = append(contacts, contact)
		}
	}
	
	response := map[string]interface{}{
		"type": "contact_list",
		"data": map[string]interface{}{
			"contacts": contacts,
		},
	}
	
	ws.wsMutex.RLock()
	for conn, _ := range ws.wsClients {
		if err := conn.WriteJSON(response); err != nil {
			log.Printf("Error broadcasting contact list: %v", err)
		}
	}
	ws.wsMutex.RUnlock()
}

// Additional helper methods for monitoring
func (ws *WebServer) updateGroupChatStatus() {
	// Update group chat member status based on online peers
	for _, group := range ws.groupChats {
		for memberID, member := range group.Members {
			if profile, exists := ws.userProfiles[memberID]; exists {
				member.IsOnline = profile.IsOnline
			}
		}
	}
}

func (ws *WebServer) cleanupExpiredTransfers() {
	for transferID, transfer := range ws.fileTransfers {
		if time.Since(transfer.StartTime) > 24*time.Hour && transfer.Status != "completed" {
			transfer.Status = "expired"
			// Could delete the file here if needed
			log.Printf("Transfer %s expired", transferID)
		}
	}
}

// API Handlers
func (ws *WebServer) handleStatusAPI(w http.ResponseWriter, r *http.Request) {
	peerCount := 0
	if ws.node != nil {
		peerCount = len(ws.node.Peers())
	}
	
	status := map[string]interface{}{
		"node_id":         "",
		"peer_count":      peerCount,
		"active_sessions": len(ws.wsClients),
		"uptime":          time.Since(time.Now()).String(),
	}
	
	if ws.node != nil {
		status["node_id"] = ws.node.ID().String()
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (ws *WebServer) handlePeersAPI(w http.ResponseWriter, r *http.Request) {
	peers := make([]map[string]interface{}, 0)
	
	if ws.node != nil {
		for _, peerID := range ws.node.Peers() {
			peer := map[string]interface{}{
				"peer_id": peerID.String(),
				"online":  true,
			}
			
			if profile, exists := ws.userProfiles[peerID.String()]; exists {
				peer["display_name"] = profile.DisplayName
				peer["status"] = profile.Status
				peer["last_seen"] = profile.LastSeen
			}
			
			peers = append(peers, peer)
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"peers": peers,
	})
}

func (ws *WebServer) handleSearchAPI(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	searchType := r.URL.Query().Get("type")
	
	results := make([]map[string]interface{}, 0)
	
	// Simple search implementation
	if ws.node != nil {
		for _, peerID := range ws.node.Peers() {
			peerStr := peerID.String()
			if strings.Contains(strings.ToLower(peerStr), strings.ToLower(query)) {
				result := map[string]interface{}{
					"peer_id": peerStr,
					"type":    searchType,
					"score":   1.0,
				}
				
				if profile, exists := ws.userProfiles[peerStr]; exists {
					result["display_name"] = profile.DisplayName
					result["status"] = profile.Status
				}
				
				results = append(results, result)
			}
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"query":   query,
		"type":    searchType,
		"results": results,
	})
}

func (ws *WebServer) handleProfileAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Return current user's profile
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Profile endpoint - GET not implemented yet",
		})
	case "POST", "PUT":
		// Update profile
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Profile updated",
		})
	}
}

func (ws *WebServer) handleAvatarUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Avatar upload not implemented yet",
	})
}

func (ws *WebServer) handleEncryptionSessions(w http.ResponseWriter, r *http.Request) {
	sessions := make([]*EncryptionSession, 0)
	for _, session := range ws.encryptionSessions {
		sessionCopy := *session
		sessionCopy.SessionKey = nil // Don't expose keys
		sessions = append(sessions, &sessionCopy)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": sessions,
	})
}

func (ws *WebServer) handleKeyManagement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Key management endpoint",
	})
}

func (ws *WebServer) handleKeyExchangeAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Key exchange endpoint",
	})
}

// Utility functions
func (ws *WebServer) generateID() string {
	return common.GenerateID()
}

func (ws *WebServer) getDisplayName(peerID string) string {
	// Convert UserProfile map to generic interface map for common function
	profiles := make(map[string]interface{})
	for id, profile := range ws.userProfiles {
		profiles[id] = map[string]interface{}{
			"display_name": profile.DisplayName,
		}
	}
	return common.GetDisplayName(peerID, profiles)
}

func (ws *WebServer) isPeerOnline(peerID string) bool {
	targetPeer, err := peer.Decode(peerID)
	if err != nil {
		return false
	}
	return ws.isPeerConnected(targetPeer)
}

func (ws *WebServer) isPeerConnected(p peer.ID) bool {
	if ws.node == nil {
		return false
	}
	peers := ws.node.Peers()
	for _, peer := range peers {
		if peer == p {
			return true
		}
	}
	return false
} 