package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/qasa/network/libp2p"
	"github.com/qasa/network/message"
	"github.com/qasa/network/encryption"
)

func main() {
	// Parse command line arguments
	port := flag.Int("port", 0, "Port to listen on (0 for random port)")
	disableMDNS := flag.Bool("no-mdns", false, "Disable mDNS discovery")
	enableDHT := flag.Bool("dht", false, "Enable DHT-based peer discovery")
	requireAuth := flag.Bool("auth", false, "Require peer authentication")
	configDir := flag.String("config", ".qasa", "Configuration directory")
	disableOfflineQueue := flag.Bool("no-offline-queue", false, "Disable offline message queuing")
	bootstrapNode := flag.String("bootstrap", "", "Add a bootstrap node")
	connectTo := flag.String("connect", "", "Peer to connect to")
	flag.Parse()

	// Create a context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Configure the node
	config := libp2p.DefaultNodeConfig()
	config.ListenPort = *port
	config.EnableMDNS = !*disableMDNS
	config.EnableDHT = *enableDHT
	config.RequireAuth = *requireAuth
	config.ConfigDir = *configDir

	// Add bootstrap node if provided
	if *bootstrapNode != "" {
		config.BootstrapNodes = append(config.BootstrapNodes, *bootstrapNode)
	}

	// Initialize the libp2p node
	node, err := libp2p.NewNodeWithConfig(ctx, config)
	if err != nil {
		fmt.Printf("Failed to create libp2p node: %s\n", err)
		os.Exit(1)
	}

	// Initialize the metadata exchange protocol
	metadataExchange := libp2p.NewMetadataExchange(ctx, node)
	
	// Register metadata handlers
	metadataExchange.RegisterMetadataHandler("pq-algos", func(peerID peer.ID, value string) error {
		fmt.Printf("Peer %s supports post-quantum algorithms: %s\n", shortPeerID(peerID.String()), value)
		return nil
	})

	// Print node information
	fmt.Printf("QaSa Network Node started\n")
	fmt.Printf("Peer ID: %s\n", node.ID())
	fmt.Printf("Addresses:\n")
	for _, addr := range node.Addrs() {
		fmt.Printf("  - %s/p2p/%s\n", addr, node.ID())
	}
	fmt.Printf("mDNS Discovery: %v\n", config.EnableMDNS)
	fmt.Printf("DHT Discovery: %v\n", config.EnableDHT)
	fmt.Printf("Authentication Required: %v\n", config.RequireAuth)
	fmt.Printf("Offline Message Queue: %v\n", !*disableOfflineQueue)

	// Print bootstrap nodes if available
	bootstrapNodes, err := node.GetBootstrapNodes()
	if err == nil && len(bootstrapNodes) > 0 {
		fmt.Printf("Bootstrap Nodes:\n")
		for i, addr := range bootstrapNodes {
			fmt.Printf("  %d. %s\n", i+1, addr)
		}
	}

	// Configure chat protocol options
	chatOptions := message.DefaultChatProtocolOptions()
	chatOptions.ConfigDir = *configDir
	chatOptions.EnableOfflineQueue = !*disableOfflineQueue

	// Initialize the chat protocol
	chatProtocol := message.NewChatProtocolWithOptions(ctx, node.Host(), func(msg message.Message) {
		// Extract peer ID from the message
		peerID, err := peer.Decode(msg.From)
		if err != nil {
			fmt.Printf("Invalid peer ID in message: %s\n", err)
			return
		}
		
		if config.RequireAuth && !node.IsPeerAuthenticated(peerID) {
			fmt.Printf("\n[%s] Rejected message from unauthenticated peer %s\n> ", 
				msg.Time.Format("15:04:05"),
				shortPeerID(msg.From))
			return
		}
		
		fmt.Printf("\n[%s] %s: %s\n> ", 
			msg.Time.Format("15:04:05"),
			shortPeerID(msg.From), 
			msg.Content)
	}, chatOptions)
	chatProtocol.Start()

	// If a peer address was provided, connect to it
	if *connectTo != "" {
		fmt.Printf("Connecting to peer: %s\n", *connectTo)
		if err := node.Connect(ctx, *connectTo); err != nil {
			fmt.Printf("Failed to connect to peer: %s\n", err)
		} else {
			// Authenticate the peer
			peerIDStr := extractPeerID(*connectTo)
			if peerIDStr != "" {
				// Convert string to peer.ID
				peerID, err := peer.Decode(peerIDStr)
				if err != nil {
					fmt.Printf("Invalid peer ID: %s\n", err)
				} else {
					if _, err := node.AuthenticatePeer(peerID); err != nil {
						fmt.Printf("Failed to authenticate peer: %s\n", err)
					} else {
						fmt.Printf("Peer authenticated: %s\n", shortPeerID(peerIDStr))
						
						// Exchange metadata
						if err := metadataExchange.ExchangeMetadata(peerID); err != nil {
							fmt.Printf("Failed to exchange metadata: %s\n", err)
						} else {
							fmt.Printf("Metadata exchanged with peer: %s\n", shortPeerID(peerIDStr))
						}
					}
				}
			}
		}
	}

	// Start a goroutine to periodically print connected peers
	var peerListMutex sync.Mutex
	var connectedPeers []peer.ID
	
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				peers := node.Peers()
				
				// Update the list of connected peers
				peerListMutex.Lock()
				connectedPeers = make([]peer.ID, len(peers))
				copy(connectedPeers, peers)
				
				for _, peer := range peers {
					// Try to authenticate peers automatically if not already authenticated
					if config.RequireAuth && !node.IsPeerAuthenticated(peer) {
						if _, err := node.AuthenticatePeer(peer); err == nil {
							// Exchange metadata
							if err := metadataExchange.ExchangeMetadata(peer); err == nil {
								fmt.Printf("\nAutomatically authenticated peer: %s\n> ", shortPeerID(peer.String()))
							}
						}
					}
				}
				peerListMutex.Unlock()
				
				if len(peers) > 0 {
					fmt.Printf("\nConnected to %d peers:\n", len(peers))
					for i, peer := range peers {
						status := ""
						if node.IsPeerAuthenticated(peer) {
							status = " (authenticated)"
						}
						
						// Add offline message count if available
						if !*disableOfflineQueue {
							queuedCount := chatProtocol.GetOfflineQueuedMessageCount(peer)
							if queuedCount > 0 {
								status += fmt.Sprintf(" [%d queued msgs]", queuedCount)
							}
						}
						
						fmt.Printf("  %d. %s%s\n", i+1, peer.String(), status)
					}
					fmt.Print("> ")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Set a handler for Ctrl+C
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("\nReceived interrupt signal, shutting down...")
		cancel()
		// Wait a bit to allow cleanup
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()

	// Handle user commands
	handleUserCommands(ctx, node, chatProtocol, metadataExchange)

	// Wait for context to be canceled
	<-ctx.Done()
	fmt.Println("Shutting down...")
}

// shortPeerID returns a shortened version of a peer ID
func shortPeerID(peerID string) string {
	if len(peerID) <= 10 {
		return peerID
	}
	return peerID[:5] + "..." + peerID[len(peerID)-5:]
}

// extractPeerID extracts the peer ID from a multiaddress string
func extractPeerID(addr string) string {
	parts := strings.Split(addr, "/p2p/")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// parseIndex tries to parse a string as an index (integer)
func parseIndex(s string) (int, error) {
	var idx int
	_, err := fmt.Sscanf(s, "%d", &idx)
	return idx, err
}

// Handle user commands
func handleUserCommands(ctx context.Context, node *libp2p.Node, chatProtocol *message.ChatProtocol, metadataExchange *libp2p.MetadataExchange) {
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Println("\nCommands: 'send <peer index> <message>', 'list', 'bootstrap <addr>', 'connect <addr>', 'quit'")
	fmt.Println("Additional commands: 'key-exchange <peer index>' to initiate key exchange, 'encrypt-test' to test encryption workflow")
	fmt.Print("> ")
	
	for {
		command, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading command: %s\n", err)
			break
		}
		
		command = strings.TrimSpace(command)
		
		if command == "quit" || command == "exit" {
			fmt.Println("Exiting...")
			break
		}
		
		tokens := strings.Fields(command)
		if len(tokens) == 0 {
			fmt.Print("> ")
			continue
		}
		
		switch tokens[0] {
		case "send":
			// Send a message to a peer
			if len(tokens) < 3 {
				fmt.Println("Usage: send <peer index> <message>")
				break
			}
			
			peerIdx, err := parseIndex(tokens[1])
			if err != nil {
				fmt.Printf("Invalid peer index: %s\n", err)
				break
			}
			
			// Get the list of peers
			peers := node.Peers()
			
			if peerIdx < 0 || peerIdx >= len(peers) {
				fmt.Printf("Invalid peer index: must be between 0 and %d\n", len(peers)-1)
				break
			}
			
			message := strings.Join(tokens[2:], " ")
			peerID := peers[peerIdx]
			
			if err := chatProtocol.SendMessageToPeer(peerID.String(), message); err != nil {
				fmt.Printf("Failed to send message: %s\n", err)
			} else {
				fmt.Printf("Message sent to peer %d (%s)\n", peerIdx, shortPeerID(peerID.String()))
			}
		
		case "list":
			// List connected peers
			peers := node.Peers()
			if len(peers) == 0 {
				fmt.Println("No peers connected.")
			} else {
				fmt.Printf("Connected to %d peers:\n", len(peers))
				for i, peer := range peers {
					status := ""
					if node.IsPeerAuthenticated(peer) {
						status = " (authenticated)"
					}
					fmt.Printf("  %d. %s%s\n", i, shortPeerID(peer.String()), status)
				}
			}
		
		case "bootstrap":
			// Add a bootstrap node
			if len(tokens) < 2 {
				fmt.Println("Usage: bootstrap <address>")
				break
			}
			
			addr := tokens[1]
			if err := node.AddBootstrapNode(addr); err != nil {
				fmt.Printf("Failed to add bootstrap node: %s\n", err)
			} else {
				fmt.Printf("Added bootstrap node: %s\n", addr)
			}
		
		case "connect":
			// Connect to a peer
			if len(tokens) < 2 {
				fmt.Println("Usage: connect <address>")
				break
			}
			
			addr := tokens[1]
			if err := node.Connect(ctx, addr); err != nil {
				fmt.Printf("Failed to connect to peer: %s\n", err)
			} else {
				fmt.Printf("Connected to peer: %s\n", addr)
				
				// Try to authenticate the peer
				peerIDStr := extractPeerID(addr)
				if peerIDStr != "" {
					peerID, err := peer.Decode(peerIDStr)
					if err != nil {
						fmt.Printf("Invalid peer ID: %s\n", err)
					} else {
						if _, err := node.AuthenticatePeer(peerID); err != nil {
							fmt.Printf("Failed to authenticate peer: %s\n", err)
						} else {
							fmt.Printf("Peer authenticated: %s\n", shortPeerID(peerIDStr))
							
							// Exchange metadata
							if err := metadataExchange.ExchangeMetadata(peerID); err != nil {
								fmt.Printf("Failed to exchange metadata: %s\n", err)
							} else {
								fmt.Printf("Metadata exchanged with peer: %s\n", shortPeerID(peerIDStr))
							}
						}
					}
				}
			}
		
		case "key-exchange":
			// Initiate key exchange with a peer
			if len(tokens) < 2 {
				fmt.Println("Usage: key-exchange <peer index>")
				break
			}
			
			peerIdx, err := parseIndex(tokens[1])
			if err != nil {
				fmt.Printf("Invalid peer index: %s\n", err)
				break
			}
			
			// Get the list of peers
			peers := node.Peers()
			
			if peerIdx < 0 || peerIdx >= len(peers) {
				fmt.Printf("Invalid peer index: must be between 0 and %d\n", len(peers)-1)
				break
			}
			
			peerID := peers[peerIdx]
			
			// Initiate key exchange
			if err := chatProtocol.InitiateKeyExchange(peerID); err != nil {
				fmt.Printf("Failed to initiate key exchange: %s\n", err)
			} else {
				fmt.Printf("Key exchange initiated with peer %d (%s)\n", peerIdx, shortPeerID(peerID.String()))
			}
		
		case "encrypt-test":
			// Test the encryption/decryption workflow
			fmt.Println("Testing message encryption/decryption workflow...")
			
			// Create temporary directory
			tempDir, err := os.MkdirTemp("", "qasa-test")
			if err != nil {
				fmt.Printf("Failed to create temp directory: %v\n", err)
				break
			}
			defer os.RemoveAll(tempDir)
			
			// Get crypto provider
			provider, err := encryption.GetCryptoProvider()
			if err != nil {
				fmt.Printf("Failed to get crypto provider: %v\n", err)
				break
			}
			
			// Create message crypto
			msgCrypto, err := encryption.NewMessageCrypto(provider, tempDir)
			if err != nil {
				fmt.Printf("Failed to create message crypto: %v\n", err)
				break
			}
			
			// Get key store
			keyStore, err := encryption.NewKeyStore(tempDir)
			if err != nil {
				fmt.Printf("Failed to create key store: %v\n", err)
				break
			}
			
			// Get local peer ID
			localPeerID, err := keyStore.GetMyPeerID()
			if err != nil {
				fmt.Printf("Failed to get local peer ID: %v\n", err)
				break
			}
			
			fmt.Printf("Local peer ID: %s\n", localPeerID)
			
			// Create test message
			testMessage := []byte("This is a test message for encryption and decryption.")
			fmt.Printf("Original message: %s\n", testMessage)
			
			// Encrypt message to self
			ciphertext, err := msgCrypto.EncryptMessage(testMessage, localPeerID)
			if err != nil {
				fmt.Printf("Failed to encrypt message: %v\n", err)
				break
			}
			
			fmt.Printf("Encrypted message length: %d bytes\n", len(ciphertext))
			
			// Decrypt message
			decrypted, err := msgCrypto.DecryptMessage(ciphertext, localPeerID)
			if err != nil {
				fmt.Printf("Failed to decrypt message: %v\n", err)
				break
			}
			
			fmt.Printf("Decrypted message: %s\n", decrypted)
			
			if string(decrypted) == string(testMessage) {
				fmt.Println("Success: Encryption/decryption test passed!")
			} else {
				fmt.Println("Error: Decrypted message does not match original message!")
			}
		
		default:
			fmt.Printf("Unknown command: %s\n", tokens[0])
		}
		
		fmt.Print("> ")
	}
} 