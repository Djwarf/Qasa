// Package message provides message exchange functionality for the QaSa network
package message

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/qasa/network/encryption"
)

const (
	// ProtocolID is the ID of the chat protocol
	ProtocolID = "/qasa/chat/1.0.0"

	// MaxMessageSize is the maximum size of a message
	MaxMessageSize = 1024 * 64 // 64KB
)

// AckTimeout is the timeout for waiting for an acknowledgment
var AckTimeout = 10 * time.Second

// MessageType indicates the type of message
type MessageType string

const (
	// TypeChat indicates a regular chat message
	TypeChat MessageType = "chat"

	// TypeAck indicates an acknowledgment message
	TypeAck MessageType = "ack"

	// TypeKeyExchange indicates a key exchange message
	TypeKeyExchange MessageType = "key_exchange"

	// TypeRekey indicates a request to rotate the key
	TypeRekey MessageType = "rekey"

	// TypeKeyRotationNotice indicates a notification that keys have been rotated
	TypeKeyRotationNotice MessageType = "key_rotation_notice"
)

// Message represents a chat message
//
// This structure contains all the information about a chat message,
// including metadata and content. It is serialized to JSON for
// transmission over the network.
type Message struct {
	ID        string      `json:"id"`                  // Unique message identifier
	From      string      `json:"from"`                // Sender's peer ID
	To        string      `json:"to,omitempty"`        // Recipient's peer ID (empty for broadcasts)
	Type      MessageType `json:"type"`                // Type of message (chat, ack, key_exchange)
	Content   string      `json:"content"`             // Message content (may be encrypted)
	Time      time.Time   `json:"time"`                // Time the message was created
	Signature []byte      `json:"signature,omitempty"` // Digital signature for message verification
}

// EncryptedMessage wraps a message with encryption information
//
// This structure is used when encryption is enabled to provide
// end-to-end security for message content. The original message
// is encrypted, and additional metadata is provided for decryption.
type EncryptedMessage struct {
	ID          string    `json:"id"`         // Message ID
	From        string    `json:"from"`       // Sender's peer ID
	To          string    `json:"to"`         // Recipient's peer ID
	Ciphertext  []byte    `json:"ciphertext"` // Encrypted message content
	MessageType string    `json:"type"`       // Type of the original message
	Timestamp   time.Time `json:"timestamp"`  // When the message was sent
	Signature   []byte    `json:"signature"`  // Signature of the original plaintext message
}

// ChatCallback is a function that will be called when a message is received
//
// Applications can register this callback to be notified of new messages.
type ChatCallback func(message Message)

// AcknowledgeFunc is a function that acknowledges received messages
//
// This can be customized by the application if needed.
type AcknowledgeFunc func(Message) error

// PendingMessage represents a message waiting for acknowledgment
//
// This is used internally by the ChatProtocol to track messages
// that have been sent but not yet acknowledged by the recipient.
type PendingMessage struct {
	Message    Message                       // The message that was sent
	RetryCount int                           // Number of times the message has been retried
	SentAt     time.Time                     // When the message was sent
	Acked      bool                          // Whether the message has been acknowledged
	AckedAt    time.Time                     // When the message was acknowledged (if Acked is true)
	Callback   func(acked bool, msg Message) // Optional callback when ack is received or times out
}

// ChatProtocol represents the QaSa chat protocol handler
//
// This is the main component that handles the chat protocol functionality,
// including message sending/receiving, encryption, offline message queueing,
// and acknowledgment handling.
//
// It implements a reliable messaging system with the following features:
// - End-to-end encryption (optional)
// - Message acknowledgments with automatic retries
// - Offline message queueing
// - Key exchange and rotation
type ChatProtocol struct {
	host               host.Host                  // The libp2p host
	callback           ChatCallback               // Callback for received messages
	ctx                context.Context            // Context for cancellation
	cancel             context.CancelFunc         // Function to cancel the context
	streams            map[peer.ID]network.Stream // Active streams to peers
	streamsMu          sync.RWMutex               // Mutex for streams map
	pendingMsgs        map[string]*PendingMessage // Messages waiting for acknowledgment
	pendingMsgsMu      sync.RWMutex               // Mutex for pendingMsgs map
	messageCrypto      *encryption.MessageCrypto  // Crypto provider for message encryption
	AcknowledgeMessage AcknowledgeFunc            // Function to acknowledge messages
	// Offline message queue
	offlineQueue          *OfflineMessageQueue // Queue for messages to offline peers
	isOfflineQueueEnabled bool                 // Whether offline queueing is enabled

	// Key-related settings
	useEncryption bool   // Whether encryption is enabled
	configDir     string // Directory for configuration files

	// Rate limiting
	rateLimiter    *RateLimiter // Rate limiter for incoming messages
	useRateLimiter bool         // Whether rate limiting is enabled
}

// ChatProtocolOptions defines options for creating a new chat protocol
//
// This structure allows customization of the ChatProtocol behavior
// when it is created.
type ChatProtocolOptions struct {
	ConfigDir          string // Directory for configuration and key storage
	EnableOfflineQueue bool   // Whether to enable offline message queueing
	UseEncryption      bool   // Whether to enable end-to-end encryption
	HighSecurity       bool   // Whether to apply high security policy
	EnableRateLimiting bool   // Whether to enable rate limiting
}

// DefaultChatProtocolOptions returns the default options for chat protocol
//
// By default, offline queueing and encryption are enabled, and the
// configuration directory is set to ".qasa".
//
// # Returns
//
// Default options for the chat protocol
func DefaultChatProtocolOptions() *ChatProtocolOptions {
	return &ChatProtocolOptions{
		ConfigDir:          ".qasa",
		EnableOfflineQueue: true,
		UseEncryption:      true,
		HighSecurity:       true,
		EnableRateLimiting: true,
	}
}

// NewChatProtocol creates a new chat protocol handler with default options
//
// This is a convenience wrapper around NewChatProtocolWithOptions
// that uses the default options.
//
// # Parameters
//
// - ctx: Context for managing the protocol's lifecycle
// - h: libp2p host to use for networking
// - callback: Function to call when a message is received
//
// # Returns
//
// A new ChatProtocol instance
func NewChatProtocol(ctx context.Context, h host.Host, callback ChatCallback) *ChatProtocol {
	return NewChatProtocolWithOptions(ctx, h, callback, DefaultChatProtocolOptions())
}

// NewChatProtocolWithOptions creates a new chat protocol handler with the specified options
//
// This function initializes a new ChatProtocol with custom options,
// setting up the necessary handlers and components based on the provided
// configuration.
//
// # Parameters
//
// - ctx: Context for managing the protocol's lifecycle
// - h: libp2p host to use for networking
// - callback: Function to call when a message is received
// - options: Configuration options for the protocol
//
// # Returns
//
// # A new ChatProtocol instance
//
// # Security Considerations
//
// If encryption is enabled, this function will attempt to initialize the
// cryptographic components. If that fails, encryption will be disabled
// automatically, with a warning message.
func NewChatProtocolWithOptions(ctx context.Context, h host.Host, callback ChatCallback, options *ChatProtocolOptions) *ChatProtocol {
	ctx, cancel := context.WithCancel(ctx)

	cp := &ChatProtocol{
		host:                  h,
		callback:              callback,
		ctx:                   ctx,
		cancel:                cancel,
		streams:               make(map[peer.ID]network.Stream),
		pendingMsgs:           make(map[string]*PendingMessage),
		isOfflineQueueEnabled: options.EnableOfflineQueue,
		useEncryption:         options.UseEncryption,
		configDir:             options.ConfigDir,
		useRateLimiter:        options.EnableRateLimiting,
	}

	// Set the default acknowledge function
	cp.AcknowledgeMessage = cp.defaultAcknowledgeMessage

	// Set the stream handler for the chat protocol
	h.SetStreamHandler(protocol.ID(ProtocolID), cp.handleStream)

	// Initialize offline message queue if enabled
	if options.EnableOfflineQueue {
		queue, err := NewOfflineMessageQueue(options.ConfigDir)
		if err != nil {
			fmt.Printf("Warning: Failed to initialize offline message queue: %s\n", err)
			cp.isOfflineQueueEnabled = false
		} else {
			cp.offlineQueue = queue
		}
	}

	// Initialize message crypto if encryption is enabled
	if options.UseEncryption {
		provider, err := encryption.GetCryptoProvider()
		if err != nil {
			fmt.Printf("Warning: Failed to get crypto provider: %s\n", err)
			cp.useEncryption = false
		} else {
			messageCrypto, err := encryption.NewMessageCrypto(provider, options.ConfigDir)
			if err != nil {
				fmt.Printf("Warning: Failed to initialize message crypto: %s\n", err)
				cp.useEncryption = false
			} else {
				cp.messageCrypto = messageCrypto

				// Set high security policy for enhanced post-quantum protection
				if options.HighSecurity {
					cp.messageCrypto.ApplyHighSecurityPolicy()
				}

				// Verify key integrity
				if err := cp.messageCrypto.VerifyKeyIntegrity(); err != nil {
					fmt.Printf("Warning: Key integrity verification failed: %s\n", err)
					// Don't disable encryption, but log the warning
				}
			}
		}
	}

	// Initialize rate limiter if enabled
	if options.EnableRateLimiting {
		if options.HighSecurity {
			cp.rateLimiter = NewRateLimiter(HighSecurityRateLimitConfig())
		} else {
			cp.rateLimiter = NewRateLimiter(DefaultRateLimitConfig())
		}
	}

	return cp
}

// Start starts the chat protocol handler
//
// This function activates the protocol, setting up network notification
// handlers, opening streams to connected peers, and starting background
// management goroutines.
//
// It should be called after creating the ChatProtocol and before
// attempting to send or receive messages.
//
// # Security Considerations
//
// If encryption is enabled, this will start the key rotation system
// to periodically rotate encryption keys for enhanced security.
func (cp *ChatProtocol) Start() {
	// Listen for new peers
	cp.host.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, c network.Conn) {
			// Attempt to open a stream when we connect to a new peer
			go cp.openStream(c.RemotePeer())
		},
		DisconnectedF: func(n network.Network, c network.Conn) {
			// Remove the stream when a peer disconnects
			cp.streamsMu.Lock()
			delete(cp.streams, c.RemotePeer())
			cp.streamsMu.Unlock()
		},
	})

	// Try to open streams to already connected peers
	for _, peer := range cp.host.Network().Peers() {
		go cp.openStream(peer)
	}

	// Start a goroutine to handle message acknowledgments and retries
	go cp.manageAcknowledgments()

	// If offline queue is enabled, start a periodic cleanup
	if cp.isOfflineQueueEnabled && cp.offlineQueue != nil {
		go cp.manageOfflineQueue()
	}

	// If encryption is enabled, start key rotation
	if cp.useEncryption && cp.messageCrypto != nil {
		// Create a channel to receive key rotation events
		keyRotationCh := make(chan struct{}, 10)

		// Start key rotation with event notification
		cp.startKeyRotationWithNotification(cp.ctx, keyRotationCh)

		// Start a goroutine to handle key rotation events
		go func() {
			for {
				select {
				case <-keyRotationCh:
					// Notify peers about the key rotation
					if err := cp.NotifyKeyRotation(); err != nil {
						fmt.Printf("Failed to notify peers about key rotation: %s\n", err)
					}
				case <-cp.ctx.Done():
					return
				}
			}
		}()
	}
}

// manageAcknowledgments periodically checks for unacknowledged messages and retries them
//
// This is an internal function that runs in a separate goroutine to handle
// message acknowledgments. It will periodically check for messages that
// have not been acknowledged and retry them if necessary, or time them out
// after too many retries.
func (cp *ChatProtocol) manageAcknowledgments() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cp.checkPendingMessages()
		case <-cp.ctx.Done():
			return
		}
	}
}

// checkPendingMessages checks for unacknowledged messages and retries or times them out
//
// This internal function is called periodically to check the status of
// pending messages. It will:
// - Remove acknowledged messages that have been in the pending list for a while
// - Retry unacknowledged messages that have timed out
// - Give up on messages that have been retried too many times
func (cp *ChatProtocol) checkPendingMessages() {
	now := time.Now()

	cp.pendingMsgsMu.Lock()
	defer cp.pendingMsgsMu.Unlock()

	for id, pending := range cp.pendingMsgs {
		if pending.Acked {
			// If message is acknowledged and old enough, remove it from pending
			if now.Sub(pending.AckedAt) > 1*time.Minute {
				delete(cp.pendingMsgs, id)
			}
			continue
		}

		// Check if message has timed out waiting for acknowledgment
		if now.Sub(pending.SentAt) > AckTimeout {
			if pending.RetryCount < 3 {
				// Retry sending the message
				pending.RetryCount++
				pending.SentAt = now

				// Extract peer ID
				peerID, err := peer.Decode(pending.Message.To)
				if err != nil {
					fmt.Printf("Failed to decode peer ID '%s': %s\n", pending.Message.To, err)
					continue
				}

				// Try to resend the message
				if err := cp.sendMessageToPeer(peerID, pending.Message); err != nil {
					fmt.Printf("Failed to retry message to %s: %s\n", peerID.String(), err)
				} else {
					fmt.Printf("Retrying message to %s (attempt %d)\n", peerID.String(), pending.RetryCount)
				}
			} else {
				// Message exceeded retry count, consider it failed
				fmt.Printf("Message to %s timed out after %d attempts\n", pending.Message.To, pending.RetryCount)

				// Call the callback if provided
				if pending.Callback != nil {
					pending.Callback(false, pending.Message)
				}

				// Remove from pending
				delete(cp.pendingMsgs, id)
			}
		}
	}
}

// manageOfflineQueue periodically cleans up expired messages and tries to deliver queued messages
func (cp *ChatProtocol) manageOfflineQueue() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	// Shorter ticker for delivering queued messages
	deliveryTicker := time.NewTicker(1 * time.Minute)
	defer deliveryTicker.Stop()

	for {
		select {
		case <-ticker.C:
			// Cleanup expired messages
			if removed := cp.offlineQueue.CleanupExpiredMessages(); removed > 0 {
				fmt.Printf("Removed %d expired offline messages\n", removed)
			}
		case <-deliveryTicker.C:
			// Try to deliver queued messages to connected peers
			cp.tryDeliverOfflineMessages()
		case <-cp.ctx.Done():
			return
		}
	}
}

// tryDeliverOfflineMessages attempts to deliver queued messages to connected peers
func (cp *ChatProtocol) tryDeliverOfflineMessages() {
	if !cp.isOfflineQueueEnabled || cp.offlineQueue == nil {
		return
	}

	// Get all peers with queued messages
	peers := cp.offlineQueue.GetQueuedPeers()
	if len(peers) == 0 {
		return
	}

	// Check which peers are connected
	for _, peerID := range peers {
		if cp.host.Network().Connectedness(peerID) == network.Connected {
			// Peer is connected, get their queued messages
			messages, err := cp.offlineQueue.GetQueuedMessages(peerID)
			if err != nil {
				fmt.Printf("Error retrieving queued messages for peer %s: %s\n", peerID, err)
				continue
			}

			if len(messages) == 0 {
				continue
			}

			fmt.Printf("Delivering %d offline messages to peer %s\n", len(messages), peerID)

			// Send each message
			for _, msg := range messages {
				if err := cp.sendMessageWithAck(peerID, msg); err != nil {
					fmt.Printf("Failed to deliver offline message to peer %s: %s\n", peerID, err)
					// Re-queue the message
					if err := cp.offlineQueue.QueueMessage(msg); err != nil {
						fmt.Printf("Failed to re-queue message: %s\n", err)
					}
				}
			}
		}
	}
}

// Stop stops the chat protocol handler
func (cp *ChatProtocol) Stop() {
	cp.cancel()

	// Close all streams
	cp.streamsMu.Lock()
	for _, stream := range cp.streams {
		stream.Close()
	}
	cp.streams = make(map[peer.ID]network.Stream)
	cp.streamsMu.Unlock()
}

// BroadcastMessage sends a message to all connected peers
func (cp *ChatProtocol) BroadcastMessage(content string) error {
	message := Message{
		ID:      generateMessageID(),
		From:    cp.host.ID().String(),
		Type:    TypeChat,
		Content: content,
		Time:    time.Now(),
	}

	cp.streamsMu.RLock()
	defer cp.streamsMu.RUnlock()

	for peerID, _ := range cp.streams {
		// Create a copy of the message with the recipient
		msgCopy := message
		msgCopy.To = peerID.String()

		if err := cp.sendMessageWithAck(peerID, msgCopy); err != nil {
			fmt.Printf("Failed to send message to %s: %s\n", peerID.String(), err)

			// If offline queue is enabled, queue the message for later delivery
			if cp.isOfflineQueueEnabled && cp.offlineQueue != nil {
				if err := cp.offlineQueue.QueueMessage(msgCopy); err != nil {
					fmt.Printf("Failed to queue message for peer %s: %s\n", peerID.String(), err)
				}
			}
			continue
		}
	}

	return nil
}

// SendMessageToPeer sends a message to a specific peer with acknowledgment
func (cp *ChatProtocol) SendMessageToPeer(peerID string, content string) error {
	peer, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %w", err)
	}

	message := Message{
		ID:      generateMessageID(),
		From:    cp.host.ID().String(),
		To:      peerID,
		Type:    TypeChat,
		Content: content,
		Time:    time.Now(),
	}

	// Check if peer is connected
	if cp.host.Network().Connectedness(peer) != network.Connected {
		// If offline queue is enabled, queue the message for later delivery
		if cp.isOfflineQueueEnabled && cp.offlineQueue != nil {
			fmt.Printf("Peer %s is offline, queueing message for later delivery\n", peerID)
			return cp.offlineQueue.QueueMessage(message)
		}
		return fmt.Errorf("peer is not connected")
	}

	return cp.sendMessageWithAck(peer, message)
}

// sendMessageWithAck sends a message to a peer and waits for an acknowledgment
func (cp *ChatProtocol) sendMessageWithAck(peerID peer.ID, message Message) error {
	// Track the message as pending
	pending := &PendingMessage{
		Message:    message,
		RetryCount: 0,
		SentAt:     time.Now(),
		Acked:      false,
	}

	cp.pendingMsgsMu.Lock()
	cp.pendingMsgs[message.ID] = pending
	cp.pendingMsgsMu.Unlock()

	// Send the message
	if err := cp.sendMessageToPeer(peerID, message); err != nil {
		// If sending failed, remove from pending
		cp.pendingMsgsMu.Lock()
		delete(cp.pendingMsgs, message.ID)
		cp.pendingMsgsMu.Unlock()

		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}

// defaultAcknowledgeMessage sends an acknowledgment for a received message
func (cp *ChatProtocol) defaultAcknowledgeMessage(originalMsg Message) error {
	// Extract peer ID
	peerID, err := peer.Decode(originalMsg.From)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %w", err)
	}

	// Create an acknowledgment message
	ackMsg := Message{
		ID:      generateMessageID(),
		From:    cp.host.ID().String(),
		To:      originalMsg.From,
		Type:    TypeAck,
		Content: originalMsg.ID, // Use content to store the original message ID
		Time:    time.Now(),
	}

	// Send the acknowledgment
	return cp.sendMessageToPeer(peerID, ackMsg)
}

// recordMessageAcknowledged marks a message as acknowledged
func (cp *ChatProtocol) recordMessageAcknowledged(messageID string) {
	cp.pendingMsgsMu.Lock()
	defer cp.pendingMsgsMu.Unlock()

	if pending, exists := cp.pendingMsgs[messageID]; exists {
		pending.Acked = true
		pending.AckedAt = time.Now()

		// Call the callback if provided
		if pending.Callback != nil {
			pending.Callback(true, pending.Message)
		}
	}
}

// openStream attempts to open a stream to a peer
func (cp *ChatProtocol) openStream(peerID peer.ID) (network.Stream, error) {
	// Check if we already have a stream to this peer
	cp.streamsMu.RLock()
	stream, exists := cp.streams[peerID]
	cp.streamsMu.RUnlock()

	if exists {
		return stream, nil
	}

	// Open a new stream
	ctx, cancel := context.WithTimeout(cp.ctx, 10*time.Second)
	defer cancel()

	stream, err := cp.host.NewStream(ctx, peerID, protocol.ID(ProtocolID))
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	// Store the stream
	cp.streamsMu.Lock()
	cp.streams[peerID] = stream
	cp.streamsMu.Unlock()

	// Start reading from the stream
	go cp.readMessages(stream, peerID)

	return stream, nil
}

// handleStream is called when we receive a new stream from a peer
func (cp *ChatProtocol) handleStream(stream network.Stream) {
	peer := stream.Conn().RemotePeer()

	// Store the stream
	cp.streamsMu.Lock()
	cp.streams[peer] = stream
	cp.streamsMu.Unlock()

	// Start reading messages from the stream
	go cp.readMessages(stream, peer)
}

// readMessages reads messages from a stream
func (cp *ChatProtocol) readMessages(stream network.Stream, peerID peer.ID) {
	reader := bufio.NewReader(stream)

	for {
		// Read a line from the stream
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Error reading from stream: %s\n", err)
			}
			break
		}

		// Check if this might be an encrypted message
		var encryptedMsg EncryptedMessage
		err = json.Unmarshal([]byte(line), &encryptedMsg)

		if err == nil && encryptedMsg.Ciphertext != nil && cp.useEncryption && cp.messageCrypto != nil {
			// Process as encrypted message
			cp.handleEncryptedMessage(encryptedMsg, peerID)
		} else {
			// Process as plaintext message
			var message Message
			if err := json.Unmarshal([]byte(line), &message); err != nil {
				fmt.Printf("Error unmarshaling message: %s\n", err)
				continue
			}

			cp.handlePlaintextMessage(message, peerID)
		}
	}

	// Remove the stream when it's closed
	cp.streamsMu.Lock()
	delete(cp.streams, peerID)
	cp.streamsMu.Unlock()
}

// handleEncryptedMessage processes an encrypted message
func (cp *ChatProtocol) handleEncryptedMessage(encryptedMsg EncryptedMessage, peerID peer.ID) {
	// Decrypt the message
	plaintextBytes, err := cp.messageCrypto.DecryptMessage(encryptedMsg.Ciphertext, peerID.String())
	if err != nil {
		fmt.Printf("Error decrypting message: %s\n", err)
		return
	}

	// Unmarshal the plaintext message
	var message Message
	if err := json.Unmarshal(plaintextBytes, &message); err != nil {
		fmt.Printf("Error unmarshaling decrypted message: %s\n", err)
		return
	}

	// Verify the signature
	valid, err := cp.messageCrypto.VerifySignature(plaintextBytes, encryptedMsg.Signature, peerID.String())
	if err != nil {
		fmt.Printf("Error verifying message signature: %s\n", err)
		// Continue processing even if verification fails
	} else if !valid {
		fmt.Printf("Warning: Invalid signature for message from %s\n", peerID.String())
		// Continue processing even if verification fails
	}

	// Process the message
	cp.handlePlaintextMessage(message, peerID)
}

// handlePlaintextMessage processes a plaintext message
func (cp *ChatProtocol) handlePlaintextMessage(message Message, peerID peer.ID) {
	// Set the From field if not already set
	if message.From == "" {
		message.From = peerID.String()
	}

	// Apply rate limiting if enabled
	if cp.useRateLimiter && cp.rateLimiter != nil {
		// Skip rate limiting for ACK and key exchange messages
		if message.Type != TypeAck && message.Type != TypeKeyExchange && message.Type != TypeRekey {
			if !cp.rateLimiter.AllowMessage(peerID.String()) {
				fmt.Printf("Message from %s rejected due to rate limiting\n", peerID.String())
				return
			}
		}
	}

	// Process based on message type
	switch message.Type {
	case TypeAck:
		// Handle acknowledgment
		cp.pendingMsgsMu.Lock()
		if pending, exists := cp.pendingMsgs[message.ID]; exists {
			pending.Acked = true
			pending.AckedAt = time.Now()

			// Call the callback if any
			if pending.Callback != nil {
				go pending.Callback(true, message)
			}
		}
		cp.pendingMsgsMu.Unlock()

	case TypeChat:
		// Call the callback with the message
		if cp.callback != nil {
			cp.callback(message)
		}

		// Send acknowledgment
		if cp.AcknowledgeMessage != nil {
			go cp.AcknowledgeMessage(message)
		}

	case TypeKeyExchange:
		// Handle key exchange message
		cp.handleKeyExchangeMessage(message, peerID)

	case TypeRekey:
		// Handle rekey request
		cp.handleRekeyRequest(message, peerID)

	case TypeKeyRotationNotice:
		// Handle key rotation notice
		cp.handleKeyRotationNotice(message, peerID)
	}
}

// handleKeyExchangeMessage processes a key exchange message
func (cp *ChatProtocol) handleKeyExchangeMessage(message Message, peerID peer.ID) {
	if !cp.useEncryption || cp.messageCrypto == nil {
		return
	}

	// Depending on the content, handle different key exchange operations
	switch message.Content {
	case "KEY_EXCHANGE_REQUEST":
		// Basic key exchange request - establish a session key
		_, err := cp.messageCrypto.EstablishSessionKey(peerID.String())
		if err != nil {
			fmt.Printf("Error establishing session key with %s: %s\n", peerID.String(), err)
			return
		}

		fmt.Printf("Established session key with peer: %s\n", peerID.String())

		// Send a response confirming key establishment
		responseMsg := Message{
			ID:      generateMessageID(),
			From:    cp.host.ID().String(),
			To:      peerID.String(),
			Type:    TypeKeyExchange,
			Content: "KEY_EXCHANGE_CONFIRMED",
			Time:    time.Now(),
		}

		cp.sendMessageToPeer(peerID, responseMsg)

	case "PUBLIC_KEY_REQUEST":
		// TODO: Implement public key request handling
		fmt.Printf("Public key request received from %s\n", peerID.String())
	}
}

// handleRekeyRequest processes a rekey request message
func (cp *ChatProtocol) handleRekeyRequest(message Message, peerID peer.ID) {
	if !cp.useEncryption || cp.messageCrypto == nil {
		return
	}

	// Process based on content
	if message.Content == "REKEY_REQUEST" {
		// Peer is requesting a new key - force rotation of our session key with them
		_, err := cp.messageCrypto.EstablishSessionKey(peerID.String())
		if err != nil {
			fmt.Printf("Error establishing new session key after rekey request from %s: %s\n", peerID.String(), err)
			return
		}

		fmt.Printf("Rekeyed with peer %s after their request\n", peerID.String())

		// Send confirmation
		responseMsg := Message{
			ID:      generateMessageID(),
			From:    cp.host.ID().String(),
			To:      peerID.String(),
			Type:    TypeRekey,
			Content: "REKEY_CONFIRMED",
			Time:    time.Now(),
		}

		cp.sendMessageToPeer(peerID, responseMsg)
	}
}

// handleKeyRotationNotice processes a key rotation notice message
func (cp *ChatProtocol) handleKeyRotationNotice(message Message, peerID peer.ID) {
	if !cp.useEncryption || cp.messageCrypto == nil {
		return
	}

	fmt.Printf("Received key rotation notice from peer %s\n", peerID.String())

	// Request their updated public key
	// This will be handled by the key discovery protocol
	requestMsg := Message{
		ID:      generateMessageID(),
		From:    cp.host.ID().String(),
		To:      peerID.String(),
		Type:    TypeKeyExchange,
		Content: "PUBLIC_KEY_REQUEST",
		Time:    time.Now(),
	}

	cp.sendMessageToPeer(peerID, requestMsg)
}

// RequestRekey requests a new session key from a peer
func (cp *ChatProtocol) RequestRekey(peerID peer.ID) error {
	if !cp.useEncryption || cp.messageCrypto == nil {
		return fmt.Errorf("encryption not enabled")
	}

	// Create a rekey request message
	message := Message{
		ID:      generateMessageID(),
		From:    cp.host.ID().String(),
		To:      peerID.String(),
		Type:    TypeRekey,
		Content: "REKEY_REQUEST",
		Time:    time.Now(),
	}

	fmt.Printf("Requesting rekey with peer: %s\n", peerID.String())

	// Send the message
	return cp.sendMessageToPeer(peerID, message)
}

// NotifyKeyRotation notifies peers about our key rotation
func (cp *ChatProtocol) NotifyKeyRotation() error {
	if !cp.useEncryption || cp.messageCrypto == nil {
		return fmt.Errorf("encryption not enabled")
	}

	fmt.Printf("Notifying peers about key rotation\n")

	// Broadcast a key rotation notice to all connected peers
	cp.streamsMu.RLock()
	defer cp.streamsMu.RUnlock()

	for peerID := range cp.streams {
		// Create a key rotation notice message
		message := Message{
			ID:      generateMessageID(),
			From:    cp.host.ID().String(),
			To:      peerID.String(),
			Type:    TypeKeyRotationNotice,
			Content: "KEY_ROTATION_NOTICE",
			Time:    time.Now(),
		}

		// Send the message
		if err := cp.sendMessageToPeer(peerID, message); err != nil {
			fmt.Printf("Failed to notify peer %s about key rotation: %s\n", peerID.String(), err)
		}
	}

	return nil
}

// startKeyRotationWithNotification starts key rotation with notification events
func (cp *ChatProtocol) startKeyRotationWithNotification(ctx context.Context, rotationCh chan<- struct{}) {
	// First start the normal key rotation
	cp.messageCrypto.StartKeyRotation(ctx)

	// Then start a separate goroutine to monitor for key rotations
	go func() {
		// Check for key rotations once per day
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		// Get the current keys for comparison
		peerID, err := cp.messageCrypto.GetMyPeerID()
		if err != nil {
			fmt.Printf("Error getting peer ID: %s\n", err)
			return
		}

		var (
			lastKyberKey     []byte
			lastDilithiumKey []byte
		)

		// Get initial key states
		if kyberKey, err := cp.messageCrypto.GetMyPublicKey(peerID, "kyber768"); err == nil {
			lastKyberKey = kyberKey
		}

		if dilithiumKey, err := cp.messageCrypto.GetMyPublicKey(peerID, "dilithium3"); err == nil {
			lastDilithiumKey = dilithiumKey
		}

		// Monitor for changes
		for {
			select {
			case <-ticker.C:
				changed := false

				// Check if Kyber key has changed
				if currentKyberKey, err := cp.messageCrypto.GetMyPublicKey(peerID, "kyber768"); err == nil {
					if !bytesEqual(lastKyberKey, currentKyberKey) {
						lastKyberKey = currentKyberKey
						changed = true
					}
				}

				// Check if Dilithium key has changed
				if currentDilithiumKey, err := cp.messageCrypto.GetMyPublicKey(peerID, "dilithium3"); err == nil {
					if !bytesEqual(lastDilithiumKey, currentDilithiumKey) {
						lastDilithiumKey = currentDilithiumKey
						changed = true
					}
				}

				// If either key has changed, send a notification
				if changed {
					select {
					case rotationCh <- struct{}{}:
						// notification sent
					default:
						// channel full, skip notification
					}
				}

			case <-ctx.Done():
				return
			}
		}
	}()
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// generateMessageID generates a unique ID for a message
func generateMessageID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), randInt(1000, 9999))
}

// randInt generates a random integer in the given range
func randInt(min, max int) int {
	return min + time.Now().Nanosecond()%(max-min+1)
}

// GetOfflineQueuedMessageCount returns the number of queued messages for a peer
func (cp *ChatProtocol) GetOfflineQueuedMessageCount(peerID peer.ID) int {
	if !cp.isOfflineQueueEnabled || cp.offlineQueue == nil {
		return 0
	}

	messages, err := cp.offlineQueue.PeekQueuedMessages(peerID)
	if err != nil || messages == nil {
		return 0
	}

	return len(messages)
}

// sendMessageToPeer sends a message to a peer
func (cp *ChatProtocol) sendMessageToPeer(peerID peer.ID, message Message) error {
	cp.streamsMu.RLock()
	stream, exists := cp.streams[peerID]
	cp.streamsMu.RUnlock()

	if !exists {
		var err error
		stream, err = cp.openStream(peerID)
		if err != nil {
			if cp.isOfflineQueueEnabled && cp.offlineQueue != nil {
				// Queue the message for later delivery
				message.To = peerID.String() // Ensure the recipient is set
				if err := cp.offlineQueue.QueueMessage(message); err != nil {
					return fmt.Errorf("failed to queue message: %w", err)
				}
				return nil
			}
			return fmt.Errorf("failed to open stream: %w", err)
		}
	}

	// If encryption is enabled, encrypt the message
	if cp.useEncryption && cp.messageCrypto != nil {
		return cp.sendEncryptedMessageToPeer(peerID, message, stream)
	}

	// Otherwise, send as plaintext
	return cp.sendPlaintextMessageToPeer(message, stream)
}

// sendEncryptedMessageToPeer encrypts and sends a message to a peer
func (cp *ChatProtocol) sendEncryptedMessageToPeer(peerID peer.ID, message Message, stream network.Stream) error {
	// Convert the message to JSON
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Sign the plaintext message
	signature, err := cp.messageCrypto.SignMessage(messageBytes)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	// Add the signature
	message.Signature = signature

	// Re-marshal with signature
	messageBytes, err = json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message with signature: %w", err)
	}

	// Encrypt the message
	ciphertext, err := cp.messageCrypto.EncryptMessage(messageBytes, peerID.String())
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	// Create the encrypted message wrapper
	encryptedMsg := EncryptedMessage{
		ID:          message.ID,
		From:        message.From,
		To:          message.To,
		Ciphertext:  ciphertext,
		MessageType: string(message.Type),
		Timestamp:   message.Time,
		Signature:   signature,
	}

	// Marshal the encrypted message
	encryptedBytes, err := json.Marshal(encryptedMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted message: %w", err)
	}

	// Send the encrypted message
	writer := bufio.NewWriter(stream)
	if _, err := writer.Write(encryptedBytes); err != nil {
		return fmt.Errorf("failed to write encrypted message: %w", err)
	}
	if _, err := writer.WriteString("\n"); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return nil
}

// sendPlaintextMessageToPeer sends a message to a peer without encryption
func (cp *ChatProtocol) sendPlaintextMessageToPeer(message Message, stream network.Stream) error {
	// Convert the message to JSON
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Send the message
	writer := bufio.NewWriter(stream)
	if _, err := writer.Write(messageBytes); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	if _, err := writer.WriteString("\n"); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return nil
}
