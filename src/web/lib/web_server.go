package lib

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/qasa/network/discovery"
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
	wsClients           map[*websocket.Conn]*ClientSession
	wsMutex             sync.RWMutex
	identifierDiscovery *discovery.IdentifierDiscoveryService
	enhancedDiscovery   *discovery.EnhancedDiscoveryService
	
	// Enhanced features
	groupChats          map[string]*GroupChat
	fileTransfers       map[string]*FileTransfer
	activeStreams       map[string]*MediaStream
	userProfiles        map[string]*UserProfile
	encryptionSessions  map[string]*EncryptionSession
	// reputationManager   *reputation.Manager
	// securityManager     *security.Manager
	
	// Configuration
	maxFileSize         int64
	allowedFileTypes    []string
	dataDir             string
}

type ClientSession struct {
	conn           *websocket.Conn
	peerID         string
	authenticated  bool
	permissions    []string
	lastActivity   time.Time
	encryptionKey  []byte
}

type GroupChat struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Members     map[string]*GroupMember `json:"members"`
	Admin       string                 `json:"admin"`
	Created     time.Time              `json:"created"`
	LastMessage time.Time              `json:"last_message"`
	IsEncrypted bool                   `json:"is_encrypted"`
	GroupKey    []byte                 `json:"-"`
}

type GroupMember struct {
	PeerID      string    `json:"peer_id"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	JoinedAt    time.Time `json:"joined_at"`
	IsOnline    bool      `json:"is_online"`
}

type FileTransfer struct {
	ID           string    `json:"id"`
	From         string    `json:"from"`
	To           string    `json:"to"`
	FileName     string    `json:"file_name"`
	FileSize     int64     `json:"file_size"`
	MimeType     string    `json:"mime_type"`
	Progress     float64   `json:"progress"`
	Status       string    `json:"status"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	FilePath     string    `json:"-"`
	IsEncrypted  bool      `json:"is_encrypted"`
}

type MediaStream struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // "audio", "video", "screen"
	Participants map[string]bool   `json:"participants"`
	Started     time.Time         `json:"started"`
	Quality     string            `json:"quality"`
	IsEncrypted bool              `json:"is_encrypted"`
}

type UserProfile struct {
	PeerID      string            `json:"peer_id"`
	DisplayName string            `json:"display_name"`
	Avatar      string            `json:"avatar"`
	Status      string            `json:"status"`
	Bio         string            `json:"bio"`
	Location    string            `json:"location"`
	PublicKeys  map[string]string `json:"public_keys"`
	Preferences map[string]interface{} `json:"preferences"`
	LastSeen    time.Time         `json:"last_seen"`
	IsOnline    bool              `json:"is_online"`
}

type EncryptionSession struct {
	PeerID        string    `json:"peer_id"`
	SessionKey    []byte    `json:"-"`
	Algorithm     string    `json:"algorithm"`
	KeyExchanged  bool      `json:"key_exchanged"`
	LastUsed      time.Time `json:"last_used"`
	MessageCount  int       `json:"message_count"`
}

func NewWebServer(node *libp2p.Node, chatProtocol *message.ChatProtocol, identifierDiscovery *discovery.IdentifierDiscoveryService, enhancedDiscovery *discovery.EnhancedDiscoveryService) *WebServer {
	dataDir := filepath.Join(os.Getenv("HOME"), ".qasa", "web")
	os.MkdirAll(dataDir, 0755)
	os.MkdirAll(filepath.Join(dataDir, "uploads"), 0755)
	os.MkdirAll(filepath.Join(dataDir, "downloads"), 0755)
	os.MkdirAll(filepath.Join(dataDir, "avatars"), 0755)

	ws := &WebServer{
		node:                node,
		chatProtocol:        chatProtocol,
		wsClients:           make(map[*websocket.Conn]*ClientSession),
		identifierDiscovery: identifierDiscovery,
		enhancedDiscovery:   enhancedDiscovery,
		
		groupChats:          make(map[string]*GroupChat),
		fileTransfers:       make(map[string]*FileTransfer),
		activeStreams:       make(map[string]*MediaStream),
		userProfiles:        make(map[string]*UserProfile),
		encryptionSessions:  make(map[string]*EncryptionSession),
		
		maxFileSize:      100 * 1024 * 1024, // 100MB
		allowedFileTypes: []string{".txt", ".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip"},
		dataDir:          dataDir,
	}

	// Initialize managers (simplified for now)
	// ws.reputationManager = reputation.NewManager()
	// ws.securityManager = security.NewManager()

	// Register message handlers
	go ws.monitorMessagesAndPeers()
	go ws.cleanupExpiredSessions()

	return ws
}

// Enhanced monitoring with better performance and feature tracking
func (ws *WebServer) monitorMessagesAndPeers() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var lastPeerCount int
	lastPeerList := make([]peer.ID, 0)

	for range ticker.C {
		// Get current peers
		currentPeers := ws.node.Peers()

		// Check if peer list has changed
		if len(currentPeers) != lastPeerCount || !peerListsEqual(currentPeers, lastPeerList) {
			// Update our tracking
			lastPeerCount = len(currentPeers)
			lastPeerList = make([]peer.ID, len(currentPeers))
			copy(lastPeerList, currentPeers)

			// Update user profiles with online status
			ws.updateOnlineStatus(currentPeers)

			// Broadcast updated peer list
			ws.BroadcastContactList()
		}

		// Update group chat member status
		ws.updateGroupChatStatus()
		
		// Clean up expired file transfers
		ws.cleanupExpiredTransfers()
	}
}

func (ws *WebServer) cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ws.wsMutex.Lock()
		for conn, session := range ws.wsClients {
			if time.Since(session.lastActivity) > 30*time.Minute {
				conn.Close()
				delete(ws.wsClients, conn)
			}
		}
		ws.wsMutex.Unlock()
	}
}

func (ws *WebServer) Start(port int) error {
	router := mux.NewRouter()

	// Serve static files from web directory
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("/app/web/static/"))))
	
	// Serve main web interface files
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/app/web/index.html")
	})
	router.Handle("/index.html", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/app/web/index.html")
	}))
	router.Handle("/styles.css", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/app/web/styles.css")
	}))
	router.Handle("/app.js", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/app/web/app.js")
	}))
	router.Handle("/utils.js", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/app/web/utils.js")
	}))
	router.Handle("/favicon.svg", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/app/web/favicon.svg")
	}))

	// WebSocket endpoint
	router.HandleFunc("/ws", ws.handleWebSocket)

	// API v1 endpoints
	api := router.PathPrefix("/api").Subrouter()
	
	// Core endpoints
	api.HandleFunc("/status", ws.handleStatusAPI).Methods("GET")
	api.HandleFunc("/peers", ws.handlePeersAPI).Methods("GET")
	api.HandleFunc("/search", ws.handleSearchAPI).Methods("GET", "POST")
	
	// User management
	api.HandleFunc("/profile", ws.handleProfileAPI).Methods("GET", "POST", "PUT")
	api.HandleFunc("/profile/avatar", ws.handleAvatarUpload).Methods("POST")
	
	// Encryption and security
	api.HandleFunc("/encryption/sessions", ws.handleEncryptionSessions).Methods("GET")
	api.HandleFunc("/encryption/keys", ws.handleKeyManagement).Methods("GET", "POST", "DELETE")
	api.HandleFunc("/encryption/exchange", ws.handleKeyExchangeAPI).Methods("POST")
	
	// Additional endpoints can be added here as handlers are implemented
	// Group chat management
	// api.HandleFunc("/groups", ws.handleGroupChats).Methods("GET", "POST")
	// api.HandleFunc("/groups/{id}", ws.handleGroupChat).Methods("GET", "PUT", "DELETE")
	// api.HandleFunc("/groups/{id}/members", ws.handleGroupMembers).Methods("GET", "POST", "DELETE")
	// api.HandleFunc("/groups/{id}/messages", ws.handleGroupMessages).Methods("GET", "POST")

	// Start the server
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("🚀 Enhanced QaSa Web Interface available at http://localhost%s\n", addr)
	fmt.Printf("📊 API Documentation: http://localhost%s/api/status\n", addr)
	
	return http.ListenAndServe(addr, router)
}

func (ws *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("Failed to upgrade connection: %v\n", err)
		return
	}

	// Create session
	session := &ClientSession{
		conn:          conn,
		peerID:        ws.node.ID().String(),
		authenticated: false,
		permissions:   []string{},
		lastActivity:  time.Now(),
	}

	// Register the client
	ws.wsMutex.Lock()
	ws.wsClients[conn] = session
	ws.wsMutex.Unlock()

	// Send initial data
	ws.sendWelcomeData(session)

	// Handle incoming messages
	go ws.handleClientMessages(session)
}

func (ws *WebServer) sendWelcomeData(session *ClientSession) {
	// Send peer ID
	ws.sendToSession(session, "peer_id", map[string]string{
		"peer_id": session.peerID,
	})

	// Send initial contact list
	ws.sendContactListToSession(session)

	// Send node status
	status := ws.getNodeStatus()
	ws.sendToSession(session, "node_status", status)

	// Send user profile
	if profile, exists := ws.userProfiles[session.peerID]; exists {
		ws.sendToSession(session, "profile", profile)
	}

	// Send group chats
	ws.sendGroupChatsToSession(session)

	// Send active file transfers
	ws.sendFileTransfersToSession(session)

	// Send encryption sessions
	ws.sendEncryptionSessionsToSession(session)
}

func (ws *WebServer) handleClientMessages(session *ClientSession) {
	defer func() {
		session.conn.Close()
		ws.wsMutex.Lock()
		delete(ws.wsClients, session.conn)
		ws.wsMutex.Unlock()
	}()

	for {
		_, message, err := session.conn.ReadMessage()
		if err != nil {
			break
		}

		session.lastActivity = time.Now()

		var msg struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}

		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		// Route message to enhanced handler
		ws.handleClientMessage(session, websocket.TextMessage, message)
	}
}

// Helper methods for sending data to sessions
func (ws *WebServer) sendContactListToSession(session *ClientSession) {
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
	
	ws.sendToSession(session, "contact_list", map[string]interface{}{
		"contacts": contacts,
	})
}

func (ws *WebServer) getNodeStatus() map[string]interface{} {
	status := map[string]interface{}{
		"node_id":         "",
		"peer_count":      0,
		"active_sessions": len(ws.wsClients),
		"uptime":          time.Since(time.Now()).String(),
	}
	
	if ws.node != nil {
		status["node_id"] = ws.node.ID().String()
		status["peer_count"] = len(ws.node.Peers())
	}
	
	return status
}

func (ws *WebServer) sendGroupChatsToSession(session *ClientSession) {
	groups := make([]*GroupChat, 0)
	for _, group := range ws.groupChats {
		groups = append(groups, group)
	}
	
	ws.sendToSession(session, "group_chats", map[string]interface{}{
		"groups": groups,
	})
}

func (ws *WebServer) sendFileTransfersToSession(session *ClientSession) {
	transfers := make([]*FileTransfer, 0)
	for _, transfer := range ws.fileTransfers {
		transfers = append(transfers, transfer)
	}
	
	ws.sendToSession(session, "file_transfers", map[string]interface{}{
		"transfers": transfers,
	})
}

func (ws *WebServer) sendEncryptionSessionsToSession(session *ClientSession) {
	sessions := make([]*EncryptionSession, 0)
	for _, encSession := range ws.encryptionSessions {
		// Don't send session keys
		sessionCopy := *encSession
		sessionCopy.SessionKey = nil
		sessions = append(sessions, &sessionCopy)
	}
	
	ws.sendToSession(session, "encryption_sessions", map[string]interface{}{
		"sessions": sessions,
	})
}

func (ws *WebServer) sendToSession(session *ClientSession, msgType string, data interface{}) {
	message := struct {
		Type string      `json:"type"`
		Data interface{} `json:"data"`
	}{
		Type: msgType,
		Data: data,
	}

	if err := session.conn.WriteJSON(message); err != nil {
		log.Printf("Failed to send message to session: %v", err)
	}
}
