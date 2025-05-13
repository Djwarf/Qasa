package message

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// OfflineQueueDir is the directory name for storing offline messages
	OfflineQueueDir = "offline_messages"

	// MaxQueuedMessagesPerPeer is the maximum number of messages that can be queued for a single peer
	MaxQueuedMessagesPerPeer = 100

	// MaxMessageAge is the maximum age of a queued message before it's discarded
	MaxMessageAge = 72 * time.Hour // 3 days
)

// OfflineMessageQueue manages messages for peers that are currently offline
type OfflineMessageQueue struct {
	baseDir    string
	mutex      sync.RWMutex
	queues     map[peer.ID][]Message
	initialized bool
}

// NewOfflineMessageQueue creates a new offline message queue
func NewOfflineMessageQueue(baseDir string) (*OfflineMessageQueue, error) {
	queueDir := filepath.Join(baseDir, OfflineQueueDir)
	
	// Ensure the queue directory exists
	if err := os.MkdirAll(queueDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create offline message directory: %w", err)
	}
	
	queue := &OfflineMessageQueue{
		baseDir:  queueDir,
		queues:   make(map[peer.ID][]Message),
	}
	
	// Load existing queued messages
	if err := queue.loadAllQueues(); err != nil {
		return nil, fmt.Errorf("failed to load offline messages: %w", err)
	}
	
	queue.initialized = true
	return queue, nil
}

// QueueMessage adds a message to the queue for an offline peer
func (q *OfflineMessageQueue) QueueMessage(msg Message) error {
	peerID, err := peer.Decode(msg.To)
	if err != nil {
		return fmt.Errorf("invalid peer ID in message: %w", err)
	}
	
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	// Get or create the queue for this peer
	queue, exists := q.queues[peerID]
	if !exists {
		queue = make([]Message, 0)
	}
	
	// Check if we've reached the maximum queue size
	if len(queue) >= MaxQueuedMessagesPerPeer {
		// Remove the oldest message to make room
		queue = queue[1:]
	}
	
	// Add the message to the queue
	queue = append(queue, msg)
	q.queues[peerID] = queue
	
	// Save the updated queue
	return q.saveQueue(peerID)
}

// GetQueuedMessages retrieves all queued messages for a peer and clears the queue
func (q *OfflineMessageQueue) GetQueuedMessages(peerID peer.ID) ([]Message, error) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	queue, exists := q.queues[peerID]
	if !exists || len(queue) == 0 {
		return nil, nil
	}
	
	// Make a copy of the messages
	messages := make([]Message, len(queue))
	copy(messages, queue)
	
	// Clear the queue
	delete(q.queues, peerID)
	
	// Remove the queue file
	queueFile := q.getQueueFilePath(peerID)
	if err := os.Remove(queueFile); err != nil && !os.IsNotExist(err) {
		return messages, fmt.Errorf("failed to remove queue file: %w", err)
	}
	
	return messages, nil
}

// PeekQueuedMessages retrieves queued messages without removing them from the queue
func (q *OfflineMessageQueue) PeekQueuedMessages(peerID peer.ID) ([]Message, error) {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	queue, exists := q.queues[peerID]
	if !exists || len(queue) == 0 {
		return nil, nil
	}
	
	// Make a copy of the messages
	messages := make([]Message, len(queue))
	copy(messages, queue)
	
	return messages, nil
}

// GetQueuedPeers returns a list of peer IDs that have queued messages
func (q *OfflineMessageQueue) GetQueuedPeers() []peer.ID {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	peers := make([]peer.ID, 0, len(q.queues))
	for peerID := range q.queues {
		if len(q.queues[peerID]) > 0 {
			peers = append(peers, peerID)
		}
	}
	
	return peers
}

// CleanupExpiredMessages removes messages that are older than MaxMessageAge
func (q *OfflineMessageQueue) CleanupExpiredMessages() int {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	removed := 0
	now := time.Now()
	
	for peerID, queue := range q.queues {
		if len(queue) == 0 {
			continue
		}
		
		newQueue := make([]Message, 0, len(queue))
		for _, msg := range queue {
			if now.Sub(msg.Time) <= MaxMessageAge {
				newQueue = append(newQueue, msg)
			} else {
				removed++
			}
		}
		
		if len(newQueue) == 0 {
			// All messages were expired, remove the queue
			delete(q.queues, peerID)
			
			// Remove the queue file
			queueFile := q.getQueueFilePath(peerID)
			os.Remove(queueFile) // Ignore errors
		} else if len(newQueue) != len(queue) {
			// Some messages were removed, update the queue
			q.queues[peerID] = newQueue
			q.saveQueue(peerID) // Ignore errors
		}
	}
	
	return removed
}

// loadAllQueues loads all offline message queues from disk
func (q *OfflineMessageQueue) loadAllQueues() error {
	// Read all files in the queue directory
	files, err := os.ReadDir(q.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read offline message directory: %w", err)
	}
	
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		
		// Try to parse the filename as a peer ID
		peerIDStr := file.Name()
		peerID, err := peer.Decode(peerIDStr)
		if err != nil {
			fmt.Printf("Warning: invalid peer ID in filename: %s\n", peerIDStr)
			continue
		}
		
		// Load the queue for this peer
		if err := q.loadQueue(peerID); err != nil {
			fmt.Printf("Warning: failed to load queue for peer %s: %s\n", peerIDStr, err)
		}
	}
	
	return nil
}

// loadQueue loads the message queue for a specific peer
func (q *OfflineMessageQueue) loadQueue(peerID peer.ID) error {
	queueFile := q.getQueueFilePath(peerID)
	
	data, err := os.ReadFile(queueFile)
	if err != nil {
		return err
	}
	
	var messages []Message
	if err := json.Unmarshal(data, &messages); err != nil {
		return fmt.Errorf("failed to unmarshal messages: %w", err)
	}
	
	q.queues[peerID] = messages
	return nil
}

// saveQueue saves the message queue for a specific peer
func (q *OfflineMessageQueue) saveQueue(peerID peer.ID) error {
	queue, exists := q.queues[peerID]
	if !exists || len(queue) == 0 {
		// No messages, remove the file if it exists
		queueFile := q.getQueueFilePath(peerID)
		if err := os.Remove(queueFile); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove empty queue file: %w", err)
		}
		return nil
	}
	
	// Marshal the messages to JSON
	data, err := json.Marshal(queue)
	if err != nil {
		return fmt.Errorf("failed to marshal messages: %w", err)
	}
	
	// Write to the queue file
	queueFile := q.getQueueFilePath(peerID)
	if err := os.WriteFile(queueFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write queue file: %w", err)
	}
	
	return nil
}

// getQueueFilePath returns the path to the queue file for a specific peer
func (q *OfflineMessageQueue) getQueueFilePath(peerID peer.ID) string {
	return filepath.Join(q.baseDir, peerID.String())
} 