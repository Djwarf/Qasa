package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/qasa/network/encryption"
	"github.com/qasa/network/message"
)

func main() {
	fmt.Println("QaSa Message Encryption/Decryption Test")
	fmt.Println("======================================")

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "qasa-test")
	if err != nil {
		fmt.Printf("Failed to create temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	// Setup Alice's directory
	aliceDir := filepath.Join(tempDir, "alice")
	if err := os.MkdirAll(aliceDir, 0755); err != nil {
		fmt.Printf("Failed to create Alice's directory: %v\n", err)
		os.Exit(1)
	}

	// Setup Bob's directory
	bobDir := filepath.Join(tempDir, "bob")
	if err := os.MkdirAll(bobDir, 0755); err != nil {
		fmt.Printf("Failed to create Bob's directory: %v\n", err)
		os.Exit(1)
	}

	// Create a context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create two libp2p hosts
	aliceHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		fmt.Printf("Failed to create Alice's host: %v\n", err)
		os.Exit(1)
	}
	defer aliceHost.Close()

	bobHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		fmt.Printf("Failed to create Bob's host: %v\n", err)
		os.Exit(1)
	}
	defer bobHost.Close()

	fmt.Printf("Alice's peer ID: %s\n", aliceHost.ID())
	fmt.Printf("Bob's peer ID: %s\n", bobHost.ID())

	// Get the crypto provider first for use throughout the example
	provider, err := encryption.GetCryptoProvider()
	if err != nil {
		fmt.Printf("Failed to get crypto provider: %v\n", err)
		os.Exit(1)
	}

	// Create message crypto instances for the example
	aliceMsgCrypto, err := encryption.NewMessageCrypto(provider, aliceDir)
	if err != nil {
		fmt.Printf("Failed to create Alice's message crypto: %v\n", err)
		os.Exit(1)
	}

	bobMsgCrypto, err := encryption.NewMessageCrypto(provider, bobDir)
	if err != nil {
		fmt.Printf("Failed to create Bob's message crypto: %v\n", err)
		os.Exit(1)
	}

	// Get peer IDs as strings for easier use
	alicePeerIDStr := aliceHost.ID().String()
	bobPeerIDStr := bobHost.ID().String()

	// Test 1: Direct messaging with encryption
	fmt.Println("\nTest 1: Direct Messaging with Encryption")
	fmt.Println("----------------------------------------")

	// Set up chat protocols for Alice and Bob
	aliceCallback := make(chan message.Message, 10)
	bobCallback := make(chan message.Message, 10)

	aliceChatProtocol := message.NewChatProtocolWithOptions(ctx, aliceHost, func(msg message.Message) {
		fmt.Printf("Alice received: %s\n", msg.Content)
		aliceCallback <- msg
	}, &message.ChatProtocolOptions{
		ConfigDir:          aliceDir,
		EnableOfflineQueue: true,
		UseEncryption:      true,
	})
	aliceChatProtocol.Start()

	bobChatProtocol := message.NewChatProtocolWithOptions(ctx, bobHost, func(msg message.Message) {
		fmt.Printf("Bob received: %s\n", msg.Content)
		bobCallback <- msg
	}, &message.ChatProtocolOptions{
		ConfigDir:          bobDir,
		EnableOfflineQueue: true,
		UseEncryption:      true,
	})
	bobChatProtocol.Start()

	// Connect the hosts
	aliceInfo := peer.AddrInfo{
		ID:    aliceHost.ID(),
		Addrs: aliceHost.Addrs(),
	}
	if err := bobHost.Connect(ctx, aliceInfo); err != nil {
		fmt.Printf("Failed to connect to Alice: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Hosts connected.")

	// Exchange keys
	time.Sleep(1 * time.Second) // Wait for connection to be established
	fmt.Println("Initiating key exchange...")

	// Bob initiates key exchange with Alice using a message
	keyExchangeMsg := "KEY_EXCHANGE_REQUEST"
	err = bobChatProtocol.SendMessageToPeer(alicePeerIDStr, keyExchangeMsg)
	if err != nil {
		fmt.Printf("Failed to send key exchange request: %v\n", err)
		os.Exit(1)
	}

	// Establish session keys directly
	_, err = bobMsgCrypto.EstablishSessionKey(alicePeerIDStr)
	if err != nil {
		fmt.Printf("Failed to establish session key for Bob→Alice: %v\n", err)
		os.Exit(1)
	}

	_, err = aliceMsgCrypto.EstablishSessionKey(bobPeerIDStr)
	if err != nil {
		fmt.Printf("Failed to establish session key for Alice→Bob: %v\n", err)
		os.Exit(1)
	}

	// Wait for key exchange to complete
	time.Sleep(2 * time.Second)

	// Send an encrypted message from Bob to Alice
	testMessage := "Hello Alice! This is a secret encrypted message from Bob."
	fmt.Printf("Bob sending to Alice: %s\n", testMessage)

	err = bobChatProtocol.SendMessageToPeer(alicePeerIDStr, testMessage)
	if err != nil {
		fmt.Printf("Failed to send message from Bob to Alice: %v\n", err)
		os.Exit(1)
	}

	// Wait for message to be received
	select {
	case receivedMsg := <-aliceCallback:
		fmt.Printf("Test message received by Alice: %s\n", receivedMsg.Content)
		if receivedMsg.Content != testMessage {
			fmt.Println("ERROR: Received message content does not match sent message!")
			os.Exit(1)
		} else {
			fmt.Println("SUCCESS: Message content matches!")
		}
	case <-time.After(5 * time.Second):
		fmt.Println("ERROR: Timeout waiting for message")
		os.Exit(1)
	}

	// Test 2: Low-level encryption/decryption
	fmt.Println("\nTest 2: Low-level Encryption/Decryption")
	fmt.Println("--------------------------------------")

	fmt.Println("Using existing crypto provider and message crypto instances")

	// Get Alice's peer ID from her key store
	aliceKeyStore, err := encryption.NewKeyStore(aliceDir)
	if err != nil {
		fmt.Printf("Failed to create Alice's key store: %v\n", err)
		os.Exit(1)
	}

	alicePeerID, err := aliceKeyStore.GetMyPeerID()
	if err != nil {
		fmt.Printf("Failed to get Alice's peer ID: %v\n", err)
		os.Exit(1)
	}

	// Get Bob's peer ID from his key store
	bobKeyStore, err := encryption.NewKeyStore(bobDir)
	if err != nil {
		fmt.Printf("Failed to create Bob's key store: %v\n", err)
		os.Exit(1)
	}

	bobPeerID, err := bobKeyStore.GetMyPeerID()
	if err != nil {
		fmt.Printf("Failed to get Bob's peer ID: %v\n", err)
		os.Exit(1)
	}

	// Get Alice's public key and add it to Bob's key store
	aliceKeyPair, err := aliceKeyStore.GetMyKeyPair("kyber768")
	if err != nil {
		fmt.Printf("Failed to get Alice's key pair: %v\n", err)
		os.Exit(1)
	}

	err = bobKeyStore.AddPeerKey(alicePeerID, "kyber768", aliceKeyPair.PublicKey)
	if err != nil {
		fmt.Printf("Failed to add Alice's public key to Bob's key store: %v\n", err)
		os.Exit(1)
	}

	// Get Bob's public key and add it to Alice's key store
	bobKeyPair, err := bobKeyStore.GetMyKeyPair("kyber768")
	if err != nil {
		fmt.Printf("Failed to get Bob's key pair: %v\n", err)
		os.Exit(1)
	}

	err = aliceKeyStore.AddPeerKey(bobPeerID, "kyber768", bobKeyPair.PublicKey)
	if err != nil {
		fmt.Printf("Failed to add Bob's public key to Alice's key store: %v\n", err)
		os.Exit(1)
	}

	// Test direct encryption/decryption
	plaintext := []byte("This is a test message for direct encryption.")
	fmt.Printf("Original message: %s\n", plaintext)

	// Bob encrypts a message for Alice
	ciphertext, err := bobMsgCrypto.EncryptMessage(plaintext, alicePeerID)
	if err != nil {
		fmt.Printf("Failed to encrypt message: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted message: %s... (%d bytes)\n",
		hex.EncodeToString(ciphertext[:32]), len(ciphertext))

	// Alice decrypts the message from Bob
	decrypted, err := aliceMsgCrypto.DecryptMessage(ciphertext, bobPeerID)
	if err != nil {
		fmt.Printf("Failed to decrypt message: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decrypted message: %s\n", decrypted)

	// Verify that decryption worked correctly
	if string(decrypted) != string(plaintext) {
		fmt.Println("ERROR: Decrypted message does not match original message!")
		os.Exit(1)
	} else {
		fmt.Println("SUCCESS: Decrypted message matches original message.")
	}

	// Test 3: Session key establishment and usage
	fmt.Println("\nTest 3: Session Key Establishment")
	fmt.Println("-------------------------------")

	// Bob establishes a session key with Alice
	_, err = bobMsgCrypto.EstablishSessionKey(alicePeerID)
	if err != nil {
		fmt.Printf("Failed to establish session key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Session key established.")

	// Send multiple messages using the session key
	messages := []string{
		"This is the first message using the session key.",
		"This is the second message using the session key.",
		"This is the third message using the session key.",
	}

	for i, msg := range messages {
		// Bob encrypts a message for Alice using the session key
		plaintext := []byte(msg)
		fmt.Printf("Message %d: %s\n", i+1, plaintext)

		ciphertext, err := bobMsgCrypto.EncryptMessage(plaintext, alicePeerID)
		if err != nil {
			fmt.Printf("Failed to encrypt message with session key: %v\n", err)
			os.Exit(1)
		}

		// Alice decrypts the message from Bob
		decrypted, err := aliceMsgCrypto.DecryptMessage(ciphertext, bobPeerID)
		if err != nil {
			fmt.Printf("Failed to decrypt message with session key: %v\n", err)
			os.Exit(1)
		}

		// Verify that decryption worked correctly
		if string(decrypted) != string(plaintext) {
			fmt.Printf("ERROR: Decrypted message %d does not match original message!\n", i+1)
			os.Exit(1)
		} else {
			fmt.Printf("SUCCESS: Decrypted message %d matches original message.\n", i+1)
		}
	}

	fmt.Println("\nAll tests passed successfully!")
}

// Helper function to connect two hosts
func connectHosts(h1, h2 host.Host) error {
	h2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}
	return h1.Connect(context.Background(), h2Info)
}
