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
	"github.com/qasa/network/encryption"
	"github.com/qasa/network/libp2p"
	"github.com/qasa/network/message"
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
	configDir := node.GetConfigDir()

	// Print help information
	printHelp()

	for {
		fmt.Print("> ")
		command, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading command: %s\n", err)
			break
		}

		command = strings.TrimSpace(command)

		if command == "" {
			continue
		}

		if command == "quit" || command == "exit" {
			fmt.Println("Exiting...")
			break
		}

		tokens := strings.Fields(command)
		if len(tokens) == 0 {
			continue
		}

		switch tokens[0] {
		// Messaging commands
		case "send":
			handleSendCommand(tokens, node, chatProtocol)

		// Network commands
		case "list", "peers":
			handleListPeersCommand(node)
		case "bootstrap":
			handleBootstrapCommand(tokens, node)
		case "connect":
			handleConnectCommand(ctx, tokens, node, metadataExchange)
		case "key-exchange":
			handleKeyExchangeCommand(tokens, node, chatProtocol)

		// Key management commands
		case "keys":
			handleKeyManagementCommand(tokens[1:], configDir, reader)

		// Crypto testing commands
		case "encrypt-test":
			handleEncryptTestCommand(configDir)

		// Help and info commands
		case "help":
			printHelp()
		case "status":
			printNodeStatus(node, chatProtocol)
		default:
			fmt.Printf("Unknown command: %s\nType 'help' for available commands.\n", tokens[0])
		}
	}
}

// printHelp prints the help information
func printHelp() {
	fmt.Println("\nQaSa Secure Chat - Command Reference")
	fmt.Println("=====================================")

	fmt.Println("\n🔹 Messaging")
	fmt.Println("  send <peer index> <message>     Send a message to a peer")

	fmt.Println("\n🔹 Network Management")
	fmt.Println("  peers | list                    List connected peers")
	fmt.Println("  connect <address>               Connect to a peer")
	fmt.Println("  bootstrap <address>             Add a bootstrap node")
	fmt.Println("  key-exchange <peer index>       Initiate key exchange with a peer")

	fmt.Println("\n🔹 Key Management")
	fmt.Println("  keys list                       List all keys in the key store")
	fmt.Println("  keys generate <algorithm>       Generate a new key pair (kyber768 or dilithium3)")
	fmt.Println("  keys import <file>              Import a key from a file")
	fmt.Println("  keys export <peer ID> <algo>    Export a key to a file")
	fmt.Println("  keys delete <peer ID> <algo>    Delete a key from the key store")
	fmt.Println("  keys info <peer ID> <algo>      Display information about a key")
	fmt.Println("  keys rotate <algo>              Rotate a key pair")

	fmt.Println("\n🔹 System")
	fmt.Println("  status                          Display node status")
	fmt.Println("  encrypt-test                    Test encryption/decryption")
	fmt.Println("  help                            Display this help information")
	fmt.Println("  quit | exit                     Exit the application")
}

// handleSendCommand handles the send command
func handleSendCommand(tokens []string, node *libp2p.Node, chatProtocol *message.ChatProtocol) {
	if len(tokens) < 3 {
		fmt.Println("Usage: send <peer index> <message>")
		return
	}

	peerIdx, err := parseIndex(tokens[1])
	if err != nil {
		fmt.Printf("Invalid peer index: %s\n", err)
		return
	}

	// Get the list of peers
	peers := node.Peers()

	if peerIdx < 0 || peerIdx >= len(peers) {
		fmt.Printf("Invalid peer index: must be between 0 and %d\n", len(peers)-1)
		return
	}

	message := strings.Join(tokens[2:], " ")
	peerID := peers[peerIdx]

	if err := chatProtocol.SendMessageToPeer(peerID.String(), message); err != nil {
		fmt.Printf("Failed to send message: %s\n", err)
	} else {
		fmt.Printf("Message sent to peer %d (%s)\n", peerIdx, shortPeerID(peerID.String()))
	}
}

// handleListPeersCommand handles the list peers command
func handleListPeersCommand(node *libp2p.Node) {
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
}

// handleBootstrapCommand handles the bootstrap command
func handleBootstrapCommand(tokens []string, node *libp2p.Node) {
	if len(tokens) < 2 {
		fmt.Println("Usage: bootstrap <address>")
		return
	}

	addr := tokens[1]
	if err := node.AddBootstrapNode(addr); err != nil {
		fmt.Printf("Failed to add bootstrap node: %s\n", err)
	} else {
		fmt.Printf("Added bootstrap node: %s\n", addr)
	}
}

// handleConnectCommand handles the connect command
func handleConnectCommand(ctx context.Context, tokens []string, node *libp2p.Node, metadataExchange *libp2p.MetadataExchange) {
	if len(tokens) < 2 {
		fmt.Println("Usage: connect <address>")
		return
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
}

// handleKeyExchangeCommand handles the key-exchange command
func handleKeyExchangeCommand(tokens []string, node *libp2p.Node, chatProtocol *message.ChatProtocol) {
	if len(tokens) < 2 {
		fmt.Println("Usage: key-exchange <peer index>")
		return
	}

	peerIdx, err := parseIndex(tokens[1])
	if err != nil {
		fmt.Printf("Invalid peer index: %s\n", err)
		return
	}

	// Get the list of peers
	peers := node.Peers()

	if peerIdx < 0 || peerIdx >= len(peers) {
		fmt.Printf("Invalid peer index: must be between 0 and %d\n", len(peers)-1)
		return
	}

	peerID := peers[peerIdx]

	// Send a key exchange request message
	keyExchangeMsg := "KEY_EXCHANGE_REQUEST"
	if err := chatProtocol.SendMessageToPeer(peerID.String(), keyExchangeMsg); err != nil {
		fmt.Printf("Failed to send key exchange request: %s\n", err)
	} else {
		fmt.Printf("Key exchange request sent to peer %d (%s)\n", peerIdx, shortPeerID(peerID.String()))
	}
}

// handleKeyManagementCommand handles key management commands
func handleKeyManagementCommand(tokens []string, configDir string, reader *bufio.Reader) {
	if len(tokens) < 2 {
		printKeyManagementHelp()
		return
	}

	keyStore, err := encryption.NewKeyStore(configDir)
	if err != nil {
		fmt.Printf("Failed to access key store: %v\n", err)
		return
	}

	switch tokens[1] {
	case "list":
		// List all keys
		keys, err := keyStore.ListKeys()
		if err != nil {
			fmt.Printf("Error listing keys: %s\n", err)
			return
		}

		if len(keys) == 0 {
			fmt.Println("No keys found.")
			return
		}

		fmt.Println("Available Keys:")
		for i, key := range keys {
			fmt.Printf("%d. Type: %s, Algorithm: %s, Created: %s\n",
				i+1,
				keyType(key),
				key.Algorithm,
				key.CreatedAt.Format("2006-01-02 15:04:05"))
		}

	case "generate":
		// Generate new keys
		if len(tokens) < 3 {
			fmt.Println("Usage: key generate <algorithm>")
			fmt.Println("Available algorithms: kyber512, kyber768, kyber1024, dilithium2, dilithium3, dilithium5")
			return
		}

		algorithm := tokens[2]
		fmt.Printf("Generating new %s keys...\n", algorithm)

		key, err := keyStore.GenerateKey(algorithm)
		if err != nil {
			fmt.Printf("Error generating keys: %s\n", err)
			return
		}

		fmt.Printf("Successfully generated %s keys\n", algorithm)
		fmt.Printf("Key ID: %s\n", key.ID)
		fmt.Printf("Created: %s\n", key.CreatedAt.Format("2006-01-02 15:04:05"))

	case "export":
		// Export keys
		if len(tokens) < 3 {
			fmt.Println("Usage: key export <key_id> [output_file]")
			return
		}

		keyID := tokens[2]
		outputFile := "qasa_keys.json"
		if len(tokens) > 3 {
			outputFile = tokens[3]
		}

		fmt.Printf("Exporting key %s to %s...\n", keyID, outputFile)

		data, err := keyStore.ExportKey(keyID)
		if err != nil {
			fmt.Printf("Error exporting key: %s\n", err)
			return
		}

		err = os.WriteFile(outputFile, data, 0600)
		if err != nil {
			fmt.Printf("Error writing key file: %s\n", err)
			return
		}

		fmt.Printf("Successfully exported key to %s\n", outputFile)

	case "import":
		// Import keys
		if len(tokens) < 3 {
			fmt.Println("Usage: key import <input_file>")
			return
		}

		inputFile := tokens[2]
		fmt.Printf("Importing keys from %s...\n", inputFile)

		data, err := os.ReadFile(inputFile)
		if err != nil {
			fmt.Printf("Error reading key file: %s\n", err)
			return
		}

		key, err := keyStore.ImportKey(data)
		if err != nil {
			fmt.Printf("Error importing key: %s\n", err)
			return
		}

		fmt.Printf("Successfully imported %s key\n", key.Algorithm)
		fmt.Printf("Key ID: %s\n", key.ID)
		fmt.Printf("Created: %s\n", key.CreatedAt.Format("2006-01-02 15:04:05"))

	case "delete":
		// Delete keys
		if len(tokens) < 3 {
			fmt.Println("Usage: key delete <key_id>")
			return
		}

		keyID := tokens[2]
		fmt.Printf("Are you sure you want to delete key %s? (y/N) ", keyID)

		response, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading response: %s\n", err)
			return
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Key deletion cancelled.")
			return
		}

		err = keyStore.DeleteKey(keyID)
		if err != nil {
			fmt.Printf("Error deleting key: %s\n", err)
			return
		}

		fmt.Printf("Successfully deleted key %s\n", keyID)

	case "rotate":
		// Rotate keys
		if len(tokens) < 3 {
			fmt.Println("Usage: key rotate <key_id>")
			return
		}

		keyID := tokens[2]
		fmt.Printf("Rotating key %s...\n", keyID)

		newKey, err := keyStore.RotateKey(keyID)
		if err != nil {
			fmt.Printf("Error rotating key: %s\n", err)
			return
		}

		fmt.Printf("Successfully rotated key\n")
		fmt.Printf("New Key ID: %s\n", newKey.ID)
		fmt.Printf("Created: %s\n", newKey.CreatedAt.Format("2006-01-02 15:04:05"))

	case "backup":
		// Backup all keys
		outputFile := "qasa_keys_backup.json"
		if len(tokens) > 2 {
			outputFile = tokens[2]
		}

		fmt.Printf("Backing up all keys to %s...\n", outputFile)

		data, err := keyStore.BackupKeys()
		if err != nil {
			fmt.Printf("Error backing up keys: %s\n", err)
			return
		}

		err = os.WriteFile(outputFile, data, 0600)
		if err != nil {
			fmt.Printf("Error writing backup file: %s\n", err)
			return
		}

		fmt.Printf("Successfully backed up keys to %s\n", outputFile)

	case "restore":
		// Restore keys from backup
		if len(tokens) < 3 {
			fmt.Println("Usage: key restore <backup_file>")
			return
		}

		backupFile := tokens[2]
		fmt.Printf("Restoring keys from %s...\n", backupFile)

		data, err := os.ReadFile(backupFile)
		if err != nil {
			fmt.Printf("Error reading backup file: %s\n", err)
			return
		}

		keys, err := keyStore.RestoreKeys(data)
		if err != nil {
			fmt.Printf("Error restoring keys: %s\n", err)
			return
		}

		fmt.Printf("Successfully restored %d keys\n", len(keys))
		for _, key := range keys {
			fmt.Printf("- %s (%s)\n", key.ID, key.Algorithm)
		}

	default:
		printKeyManagementHelp()
	}
}

func printKeyManagementHelp() {
	fmt.Println("Key Management Commands:")
	fmt.Println("  key list                    - List all available keys")
	fmt.Println("  key generate <algorithm>    - Generate new keys")
	fmt.Println("  key export <key_id> [file]  - Export a key to a file")
	fmt.Println("  key import <file>           - Import a key from a file")
	fmt.Println("  key delete <key_id>         - Delete a key")
	fmt.Println("  key rotate <key_id>         - Rotate a key")
	fmt.Println("  key backup [file]           - Backup all keys")
	fmt.Println("  key restore <file>          - Restore keys from backup")
	fmt.Println("\nAvailable algorithms:")
	fmt.Println("  - kyber512, kyber768, kyber1024")
	fmt.Println("  - dilithium2, dilithium3, dilithium5")
}

// typeFromAlgorithm returns the type of a cryptographic algorithm
func typeFromAlgorithm(algorithm string) string {
	switch algorithm {
	case "kyber768":
		return "Key Encapsulation (KEM)"
	case "dilithium3":
		return "Digital Signature"
	default:
		return "Unknown"
	}
}

// keyType returns the type of a key (local or remote)
func keyType(keyInfo *encryption.KeyInfo) string {
	if keyInfo.IsLocal {
		return "Local (public + private)"
	}
	return "Remote (public only)"
}

// handleEncryptTestCommand handles the encrypt-test command
func handleEncryptTestCommand(configDir string) {
	fmt.Println("Testing message encryption/decryption workflow...")

	// Get crypto provider
	provider, err := encryption.GetCryptoProvider()
	if err != nil {
		fmt.Printf("Failed to get crypto provider: %v\n", err)
		return
	}

	// Create message crypto
	msgCrypto, err := encryption.NewMessageCrypto(provider, configDir)
	if err != nil {
		fmt.Printf("Failed to create message crypto: %v\n", err)
		return
	}

	// Get key store
	keyStore, err := encryption.NewKeyStore(configDir)
	if err != nil {
		fmt.Printf("Failed to create key store: %v\n", err)
		return
	}

	// Get local peer ID
	localPeerID, err := keyStore.GetMyPeerID()
	if err != nil {
		fmt.Printf("Failed to get local peer ID: %v\n", err)
		return
	}

	fmt.Printf("Local peer ID: %s\n", localPeerID)

	// Create test message
	testMessage := []byte("This is a test message for encryption and decryption.")
	fmt.Printf("Original message: %s\n", testMessage)

	// Encrypt message to self
	ciphertext, err := msgCrypto.EncryptMessage(testMessage, localPeerID)
	if err != nil {
		fmt.Printf("Failed to encrypt message: %v\n", err)
		return
	}

	fmt.Printf("Encrypted message length: %d bytes\n", len(ciphertext))

	// Decrypt message
	decrypted, err := msgCrypto.DecryptMessage(ciphertext, localPeerID)
	if err != nil {
		fmt.Printf("Failed to decrypt message: %v\n", err)
		return
	}

	fmt.Printf("Decrypted message: %s\n", decrypted)

	if string(decrypted) == string(testMessage) {
		fmt.Println("Success: Encryption/decryption test passed!")
	} else {
		fmt.Println("Error: Decrypted message does not match original message!")
	}
}

// printNodeStatus prints the status of the node
func printNodeStatus(node *libp2p.Node, chatProtocol *message.ChatProtocol) {
	fmt.Println("\n📊 Node Status")
	fmt.Printf("Peer ID: %s\n", node.ID())

	// Print addresses
	fmt.Println("Listening Addresses:")
	for _, addr := range node.Addrs() {
		fmt.Printf("  - %s/p2p/%s\n", addr, node.ID())
	}

	// Network stats
	peers := node.Peers()
	fmt.Printf("Connected Peers: %d\n", len(peers))

	// Authentication status
	authedCount := 0
	for _, p := range peers {
		if node.IsPeerAuthenticated(p) {
			authedCount++
		}
	}
	fmt.Printf("Authenticated Peers: %d/%d\n", authedCount, len(peers))

	// Queue status
	queuedMsgs := 0
	for _, p := range peers {
		queuedMsgs += chatProtocol.GetOfflineQueuedMessageCount(p)
	}
	fmt.Printf("Queued Messages: %d\n", queuedMsgs)
}
