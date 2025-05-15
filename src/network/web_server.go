package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"

	"github.com/gorilla/websocket"
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
	node         *libp2p.Node
	chatProtocol *message.ChatProtocol
	wsClients    map[*websocket.Conn]bool
	wsMutex      sync.Mutex
}

func NewWebServer(node *libp2p.Node, chatProtocol *message.ChatProtocol) *WebServer {
	return &WebServer{
		node:         node,
		chatProtocol: chatProtocol,
		wsClients:    make(map[*websocket.Conn]bool),
	}
}

func (ws *WebServer) Start(port int) error {
	// Serve static files
	http.Handle("/", http.FileServer(http.Dir(filepath.Join("src", "web"))))

	// WebSocket endpoint
	http.HandleFunc("/ws", ws.handleWebSocket)

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
			}

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
			"peer_id": peer.String(),
			"online":  true,
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
