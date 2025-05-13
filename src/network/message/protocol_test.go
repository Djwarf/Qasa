package message

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestChatProtocolBasic(t *testing.T) {
	// Create two libp2p hosts
	h1, err := libp2p.New()
	if err != nil {
		t.Fatalf("Failed to create host1: %s", err)
	}
	defer h1.Close()

	h2, err := libp2p.New()
	if err != nil {
		t.Fatalf("Failed to create host2: %s", err)
	}
	defer h2.Close()

	// Connect the hosts
	h2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}
	if err := h1.Connect(context.Background(), h2Info); err != nil {
		t.Fatalf("Failed to connect hosts: %s", err)
	}

	// Create the chat protocols
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var host2ReceivedMsg Message
	var host2ReceivedMsgMu sync.Mutex

	chat1 := NewChatProtocol(ctx, h1, func(msg Message) {
		// No-op for host1
	})
	chat1.Start()

	chat2 := NewChatProtocol(ctx, h2, func(msg Message) {
		host2ReceivedMsgMu.Lock()
		host2ReceivedMsg = msg
		host2ReceivedMsgMu.Unlock()
	})
	chat2.Start()

	// Wait for the protocol to start and streams to be established
	time.Sleep(100 * time.Millisecond)

	// Send a message from host1 to host2
	testMessage := "Hello, world!"
	err = chat1.SendMessageToPeer(h2.ID().String(), testMessage)
	if err != nil {
		t.Fatalf("Failed to send message: %s", err)
	}

	// Wait for the message to be received
	time.Sleep(500 * time.Millisecond)

	// Check if host2 received the message
	host2ReceivedMsgMu.Lock()
	receivedContent := host2ReceivedMsg.Content
	host2ReceivedMsgMu.Unlock()

	if receivedContent != testMessage {
		t.Fatalf("Expected message '%s', got '%s'", testMessage, receivedContent)
	}

	// Stop the chat protocols
	chat1.Stop()
	chat2.Stop()
}

func TestMessageAcknowledgment(t *testing.T) {
	// Create two libp2p hosts
	h1, err := libp2p.New()
	if err != nil {
		t.Fatalf("Failed to create host1: %s", err)
	}
	defer h1.Close()

	h2, err := libp2p.New()
	if err != nil {
		t.Fatalf("Failed to create host2: %s", err)
	}
	defer h2.Close()

	// Connect the hosts
	h2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}
	if err := h1.Connect(context.Background(), h2Info); err != nil {
		t.Fatalf("Failed to connect hosts: %s", err)
	}

	// Create the chat protocols
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	chat1 := NewChatProtocol(ctx, h1, func(msg Message) {
		// No-op for host1
	})
	chat1.Start()

	chat2 := NewChatProtocol(ctx, h2, func(msg Message) {
		// No-op for host2
	})
	chat2.Start()

	// Wait for the protocol to start and streams to be established
	time.Sleep(100 * time.Millisecond)

	// Send a message from host1 to host2 and track if it's acknowledged
	testMessage := "Acknowledge me!"
	
	// Create a message manually to access its ID later
	messageID := generateMessageID()
	message := Message{
		ID:      messageID,
		From:    h1.ID().String(),
		To:      h2.ID().String(),
		Type:    TypeChat,
		Content: testMessage,
		Time:    time.Now(),
	}
	
	// Add a pending message to track
	ackReceived := false
	var ackMu sync.Mutex
	
	pending := &PendingMessage{
		Message:    message,
		RetryCount: 0,
		SentAt:     time.Now(),
		Acked:      false,
		Callback: func(acked bool, msg Message) {
			ackMu.Lock()
			ackReceived = acked
			ackMu.Unlock()
		},
	}
	
	chat1.pendingMsgsMu.Lock()
	chat1.pendingMsgs[messageID] = pending
	chat1.pendingMsgsMu.Unlock()
	
	// Now send the message
	err = chat1.sendMessageToPeer(h2.ID(), message)
	if err != nil {
		t.Fatalf("Failed to send message: %s", err)
	}

	// Wait for the message to be received and acknowledged
	time.Sleep(500 * time.Millisecond)

	// Check if the message was acknowledged
	ackMu.Lock()
	wasAcknowledged := ackReceived
	ackMu.Unlock()

	if !wasAcknowledged {
		t.Fatalf("Message was not acknowledged")
	}

	// Stop the chat protocols
	chat1.Stop()
	chat2.Stop()
}

func TestMessageRetry(t *testing.T) {
	// Create a host and a mock host that doesn't respond to acks
	h1, err := libp2p.New()
	if err != nil {
		t.Fatalf("Failed to create host1: %s", err)
	}
	defer h1.Close()

	h2, err := libp2p.New()
	if err != nil {
		t.Fatalf("Failed to create host2: %s", err)
	}
	defer h2.Close()

	// Connect the hosts
	h2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}
	if err := h1.Connect(context.Background(), h2Info); err != nil {
		t.Fatalf("Failed to connect hosts: %s", err)
	}

	// Create the chat protocols
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a smaller timeout for testing
	originalTimeout := AckTimeout
	AckTimeout = 100 * time.Millisecond
	defer func() { AckTimeout = originalTimeout }()

	// We'll use a custom callback for host2 that doesn't send acks
	ackSent := false
	
	chat1 := NewChatProtocol(ctx, h1, func(msg Message) {
		// No-op for host1
	})
	chat1.Start()

	// For host2, we'll create a customized chat protocol that doesn't send acks
	chat2 := NewChatProtocol(ctx, h2, func(msg Message) {
		// Intentionally not acknowledging messages
	})
	
	// Replace the acknowledge function with one that doesn't actually send acks
	originalAckFunc := chat2.AcknowledgeMessage
	chat2.AcknowledgeMessage = func(message Message) error {
		ackSent = true
		return nil // Don't actually send the ack
	}
	
	chat2.Start()

	// Wait for the protocol to start and streams to be established
	time.Sleep(200 * time.Millisecond)

	// Send a message from host1 to host2
	testMessage := "Retry me!"
	err = chat1.SendMessageToPeer(h2.ID().String(), testMessage)
	if err != nil {
		t.Fatalf("Failed to send message: %s", err)
	}

	// Manually run the pending message check to force a retry immediately
	time.Sleep(150 * time.Millisecond)
	chat1.checkPendingMessages()
	
	// Wait a bit more to ensure the retry happens
	time.Sleep(500 * time.Millisecond)

	// Ensure the mock acknowledgement function was called
	if !ackSent {
		t.Fatalf("Message acknowledgement was not called")
	}
	
	// Check if the message was retried
	chat1.pendingMsgsMu.RLock()
	var retryCount int
	var foundPending bool
	for _, pending := range chat1.pendingMsgs {
		if pending.Message.Content == testMessage {
			retryCount = pending.RetryCount
			foundPending = true
			break
		}
	}
	chat1.pendingMsgsMu.RUnlock()

	if !foundPending {
		t.Fatalf("Could not find pending message")
	}

	if retryCount == 0 {
		t.Fatalf("Message was not retried")
	} else {
		t.Logf("Message was retried %d times", retryCount)
	}

	// Restore original function (for completeness)
	chat2.AcknowledgeMessage = originalAckFunc

	// Stop the chat protocols
	chat1.Stop()
	chat2.Stop()
}

// Helper function to create and start a chat protocol
func setupChat(ctx context.Context, h host.Host, callback ChatCallback) *ChatProtocol {
	chat := NewChatProtocol(ctx, h, callback)
	chat.Start()
	return chat
} 