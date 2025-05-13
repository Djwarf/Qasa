package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/qasa/network/encryption"
)

func main() {
	fmt.Println("QaSa Crypto FFI Test")
	fmt.Println("====================")

	// Get the crypto provider
	provider, err := encryption.GetCryptoProvider()
	if err != nil {
		fmt.Printf("Failed to get crypto provider: %v\n", err)
		os.Exit(1)
	}

	// Test key generation
	fmt.Println("\n1. Testing Key Generation")
	fmt.Println("------------------------")

	// Generate Kyber key pair
	kyberKeyPair, err := provider.GenerateKeyPair("kyber768")
	if err != nil {
		fmt.Printf("Failed to generate Kyber key pair: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Kyber768 Public Key: %s... (%d bytes)\n", 
		hex.EncodeToString(kyberKeyPair.PublicKey[:32]), len(kyberKeyPair.PublicKey))
	fmt.Printf("Kyber768 Private Key: %s... (%d bytes)\n", 
		hex.EncodeToString(kyberKeyPair.PrivateKey[:32]), len(kyberKeyPair.PrivateKey))

	// Generate Dilithium key pair
	dilithiumKeyPair, err := provider.GenerateKeyPair("dilithium3")
	if err != nil {
		fmt.Printf("Failed to generate Dilithium key pair: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Dilithium3 Public Key: %s... (%d bytes)\n", 
		hex.EncodeToString(dilithiumKeyPair.PublicKey[:32]), len(dilithiumKeyPair.PublicKey))
	fmt.Printf("Dilithium3 Private Key: %s... (%d bytes)\n", 
		hex.EncodeToString(dilithiumKeyPair.PrivateKey[:32]), len(dilithiumKeyPair.PrivateKey))

	// Test encryption/decryption
	fmt.Println("\n2. Testing Encryption/Decryption")
	fmt.Println("-------------------------------")

	plaintext := []byte("Hello, QaSa! This is a test message for encryption.")
	fmt.Printf("Original Message: %s\n", plaintext)

	// Encrypt the message
	ciphertext, err := provider.Encrypt(plaintext, kyberKeyPair.PublicKey)
	if err != nil {
		fmt.Printf("Failed to encrypt message: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted Message: %s... (%d bytes)\n", 
		hex.EncodeToString(ciphertext[:32]), len(ciphertext))

	// Decrypt the message
	decrypted, err := provider.Decrypt(ciphertext, kyberKeyPair.PrivateKey)
	if err != nil {
		fmt.Printf("Failed to decrypt message: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decrypted Message: %s\n", decrypted)

	// Verify that decryption worked correctly
	if string(decrypted) != string(plaintext) {
		fmt.Println("ERROR: Decrypted message does not match original message!")
		os.Exit(1)
	} else {
		fmt.Println("Success: Decrypted message matches original message.")
	}

	// Test signing/verification
	fmt.Println("\n3. Testing Signing/Verification")
	fmt.Println("------------------------------")

	message := []byte("This is a message that needs to be signed.")
	fmt.Printf("Message to Sign: %s\n", message)

	// Sign the message
	signature, err := provider.Sign(message, dilithiumKeyPair.PrivateKey)
	if err != nil {
		fmt.Printf("Failed to sign message: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Signature: %s... (%d bytes)\n", 
		hex.EncodeToString(signature[:32]), len(signature))

	// Verify the signature
	valid, err := provider.Verify(message, signature, dilithiumKeyPair.PublicKey)
	if err != nil {
		fmt.Printf("Failed to verify signature: %v\n", err)
		os.Exit(1)
	}

	if valid {
		fmt.Println("Success: Signature verification passed.")
	} else {
		fmt.Println("ERROR: Signature verification failed!")
		os.Exit(1)
	}

	// Modify the message and verify again
	tamperedMessage := []byte("This is a TAMPERED message that needs to be signed.")
	fmt.Printf("Tampered Message: %s\n", tamperedMessage)

	// Verify with tampered message
	valid, err = provider.Verify(tamperedMessage, signature, dilithiumKeyPair.PublicKey)
	if err != nil {
		fmt.Printf("Failed to verify signature with tampered message: %v\n", err)
		os.Exit(1)
	}

	if valid {
		fmt.Println("ERROR: Signature verification passed with tampered message!")
		os.Exit(1)
	} else {
		fmt.Println("Success: Signature verification failed with tampered message, as expected.")
	}

	// Test key exchange handshake
	fmt.Println("\n4. Testing Key Exchange Handshake")
	fmt.Println("--------------------------------")

	// Create key exchange handlers
	aliceHandler, err := encryption.NewKeyExchangeHandler(provider)
	if err != nil {
		fmt.Printf("Failed to create Alice's key exchange handler: %v\n", err)
		os.Exit(1)
	}

	bobHandler, err := encryption.NewKeyExchangeHandler(provider)
	if err != nil {
		fmt.Printf("Failed to create Bob's key exchange handler: %v\n", err)
		os.Exit(1)
	}

	// Step 1: Alice initiates the handshake
	fmt.Println("Step 1: Alice initiates the handshake")
	aliceInitMsg, aliceSharedSecret, err := aliceHandler.CreateInitiatorMessage()
	if err != nil {
		fmt.Printf("Failed to create initiator message: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Alice's initiator message: %s... (%d bytes)\n", 
		hex.EncodeToString(aliceInitMsg[:32]), len(aliceInitMsg))
	fmt.Printf("Alice's shared secret: %s... (%d bytes)\n", 
		hex.EncodeToString(aliceSharedSecret[:16]), len(aliceSharedSecret))

	// Step 2: Bob processes Alice's message and creates a response
	fmt.Println("\nStep 2: Bob processes Alice's message and creates a response")
	bobResponseMsg, bobSharedSecret, err := bobHandler.ProcessInitiatorMessage(aliceInitMsg)
	if err != nil {
		fmt.Printf("Failed to process initiator message: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Bob's response message: %s... (%d bytes)\n", 
		hex.EncodeToString(bobResponseMsg[:32]), len(bobResponseMsg))
	fmt.Printf("Bob's shared secret: %s... (%d bytes)\n", 
		hex.EncodeToString(bobSharedSecret[:16]), len(bobSharedSecret))

	// Step 3: Alice processes Bob's response and creates a finalization message
	fmt.Println("\nStep 3: Alice processes Bob's response and creates a finalization message")
	aliceFinalMsg, err := aliceHandler.ProcessResponseMessage(bobResponseMsg, aliceSharedSecret)
	if err != nil {
		fmt.Printf("Failed to process response message: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Alice's finalization message: %s... (%d bytes)\n", 
		hex.EncodeToString(aliceFinalMsg[:32]), len(aliceFinalMsg))

	// Step 4: Bob processes Alice's finalization message
	fmt.Println("\nStep 4: Bob processes Alice's finalization message")
	err = bobHandler.ProcessFinalizationMessage(aliceFinalMsg, bobSharedSecret)
	if err != nil {
		fmt.Printf("Failed to process finalization message: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Success: Key exchange handshake completed!")

	fmt.Println("\nAll tests passed successfully!")
} 