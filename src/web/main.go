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

	"github.com/qasa/network/discovery"
	"github.com/qasa/network/libp2p"
	"github.com/qasa/network/message"
	"github.com/qasa/web"
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
	node, err := libp2p.NewNode(ctx, *configDir, *port)
	if err != nil {
		log.Fatal("Failed to create node:", err)
	}

	fmt.Printf("Node started with ID: %s\n", node.ID().String())
	fmt.Printf("Listening on addresses:\n")
	for _, addr := range node.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, node.ID().String())
	}

	// Enable discovery services
	if *enableMDNS {
		if err := node.EnableMDNS(); err != nil {
			log.Fatal("Failed to enable mDNS:", err)
		}
		fmt.Println("mDNS discovery enabled")
	}

	var dhtDiscovery *discovery.DHTService
	if *enableDHT {
		if err := node.EnableDHT(); err != nil {
			log.Fatal("Failed to enable DHT:", err)
		}
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
		}
	}

	// Create the chat protocol
	chatProtocol := message.NewChatProtocol(ctx, node.Host(), func(msg message.Message) {
		fmt.Printf("Received message from %s: %s\n", msg.From, msg.Content)
	})

	// Start the chat protocol
	chatProtocol.Start()

	// Create and start the web server
	webServer := web.NewWebServer(node, chatProtocol, identifierDiscovery)
	go func() {
		if err := webServer.Start(*webPort); err != nil {
			log.Fatal("Web server error:", err)
		}
	}()

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