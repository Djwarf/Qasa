package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/qasa/network/discovery"
	"github.com/qasa/network/libp2p"
	"github.com/qasa/network/message"
	"github.com/qasa/web/lib"
)

func main() {
	// Parse command line flags
	port := flag.Int("port", 9000, "Port to listen on")
	configDir := flag.String("config", "", "Configuration directory")
	enableMDNS := flag.Bool("mdns", true, "Enable mDNS discovery")
	enableDHT := flag.Bool("dht", true, "Enable DHT discovery")
	webPort := flag.Int("web-port", 8080, "Web interface port")
	username := flag.String("username", "", "Set a username for this node")
	flag.Parse()

	// Set up configuration directory
	if *configDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Failed to get home directory:", err)
		}
		*configDir = filepath.Join(homeDir, ".qasa")
	}

	// Create node context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a new libp2p node
	config := libp2p.DefaultNodeConfig()
	config.ListenPort = *port
	config.ConfigDir = *configDir
	config.EnableMDNS = *enableMDNS
	config.EnableDHT = *enableDHT
	
	node, err := libp2p.NewNodeWithConfig(ctx, config)
	if err != nil {
		log.Fatal("Failed to create node:", err)
	}

	fmt.Printf("Node started with ID: %s\n", node.ID().String())
	fmt.Printf("Listening on addresses:\n")
	for _, addr := range node.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, node.ID().String())
	}

	// Discovery services are already enabled through config
	if *enableMDNS {
		fmt.Println("mDNS discovery enabled")
	}

	var dhtDiscovery *discovery.DHTService
	if *enableDHT {
		fmt.Println("DHT discovery enabled")
		// Get the DHT service for use with the identifier discovery
		dhtDiscovery = node.GetDHTService()
	}

	// Create the identifier discovery service
	var identifierDiscovery *discovery.IdentifierDiscoveryService
	if dhtDiscovery != nil {
		identifierDiscovery, err = discovery.NewIdentifierDiscoveryService(ctx, node.Host(), dhtDiscovery.GetDHT(), *configDir)
		if err != nil {
			log.Printf("Warning: Failed to initialize identifier discovery: %v", err)
		} else {
			// Start identifier discovery in a goroutine to prevent blocking
			go func() {
				if err := identifierDiscovery.Start(); err != nil {
					log.Printf("Warning: Failed to start identifier discovery: %v", err)
				} else {
					fmt.Println("Identifier-based discovery enabled")

					// Set username if provided
					if *username != "" {
						err := identifierDiscovery.SetSelfIdentifier(*username, "", nil)
						if err != nil {
							log.Printf("Warning: Failed to set username: %v", err)
						} else {
							fmt.Printf("Username set to: %s\n", *username)
						}
					}
				}
			}()
		}
	}

	// Create the chat protocol
	chatProtocol := message.NewChatProtocol(ctx, node.Host(), func(msg message.Message) {
		fmt.Printf("Received message from %s: %s\n", msg.From, msg.Content)
	})

	// Start the chat protocol
	chatProtocol.Start()

	// Initialize enhanced discovery if DHT is available
	var enhancedDiscovery *discovery.EnhancedDiscoveryService
	if dhtDiscovery != nil {
		discoveryConfig := discovery.DefaultDiscoveryConfig()
		discoveryConfig.EnableMDNS = *enableMDNS
		discoveryConfig.EnableDHT = *enableDHT
		discoveryConfig.EnableIdentifier = true
		
		enhancedDiscovery, err = discovery.NewEnhancedDiscoveryService(ctx, node.Host(), dhtDiscovery.GetDHT(), discoveryConfig)
		if err != nil {
			log.Printf("Warning: Failed to initialize enhanced discovery: %v", err)
		} else {
			go func() {
				if err := enhancedDiscovery.Start(); err != nil {
					log.Printf("Warning: Failed to start enhanced discovery: %v", err)
				} else {
					fmt.Println("🚀 Enhanced discovery service enabled")
				}
			}()
		}
	}

	// Create and start the web server
	fmt.Printf("Creating web server on port %d...\n", *webPort)
	webServer := lib.NewWebServer(node, chatProtocol, identifierDiscovery, enhancedDiscovery)
	
	// Give the node setup a moment to complete
	time.Sleep(500 * time.Millisecond)
	
	go func() {
		fmt.Printf("Starting web server...\n")
		if err := webServer.Start(*webPort); err != nil {
			log.Printf("Web server error: %v", err)
		}
	}()
	
	// Give the web server a moment to start
	time.Sleep(1 * time.Second)
	fmt.Printf("🌐 Web interface should be available at http://localhost:%d\n", *webPort)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("Shutting down...")

	// Stop the identifier discovery service
	if identifierDiscovery != nil {
		identifierDiscovery.Stop()
	}

	// Stop the chat protocol
	chatProtocol.Stop()

	// Shutdown node
	node.Close()
} 