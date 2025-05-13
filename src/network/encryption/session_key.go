package encryption

import (
	"crypto/rand"
	"sync"
	"time"
)

// SessionKey represents a cached session key for efficient communication
type SessionKey struct {
	Key       []byte
	ExpiresAt int64
	PeerID    string
}

// IsExpired checks if a session key has expired
func (sk *SessionKey) IsExpired() bool {
	return sk.ExpiresAt < time.Now().Unix()
}

// SessionManager handles session key management with perfect forward secrecy
type SessionManager struct {
	// Maps peer IDs to a map of key IDs to session keys
	// This allows multiple active session keys per peer for rotation
	sessions      map[string]map[uint64]*SessionKey
	sessionsById  map[uint64]*SessionKey
	nextKeyID     uint64
	rotationCount map[string]int
	mutex         sync.RWMutex
	
	// Configuration
	keyLifetime       time.Duration
	rotationInterval  time.Duration
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:         make(map[string]map[uint64]*SessionKey),
		sessionsById:     make(map[uint64]*SessionKey),
		rotationCount:    make(map[string]int),
		nextKeyID:        1,
		keyLifetime:      1 * time.Hour,     // Default key lifetime: 1 hour
		rotationInterval: 5 * time.Minute,   // Default rotation interval: 5 minutes
	}
}

// SetKeyLifetime sets the lifetime for session keys
func (sm *SessionManager) SetKeyLifetime(duration time.Duration) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.keyLifetime = duration
}

// SetRotationInterval sets the interval for key rotation
func (sm *SessionManager) SetRotationInterval(duration time.Duration) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.rotationInterval = duration
}

// StoreSessionKey adds a new session key for a peer
func (sm *SessionManager) StoreSessionKey(peerID string, key []byte) uint64 {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// Generate a unique ID for this key
	keyID := sm.nextKeyID
	sm.nextKeyID++
	
	// Create a session key with expiration time
	sessionKey := &SessionKey{
		Key:       key,
		ExpiresAt: time.Now().Add(sm.keyLifetime).Unix(),
		PeerID:    peerID,
	}
	
	// Create the peer's session map if it doesn't exist
	if _, exists := sm.sessions[peerID]; !exists {
		sm.sessions[peerID] = make(map[uint64]*SessionKey)
	}
	
	// Store the key
	sm.sessions[peerID][keyID] = sessionKey
	sm.sessionsById[keyID] = sessionKey
	
	return keyID
}

// GetCurrentSessionKey gets the most recent valid session key for a peer
func (sm *SessionManager) GetCurrentSessionKey(peerID string) (*SessionKey, uint64, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	// Check if we have any sessions for this peer
	peerSessions, exists := sm.sessions[peerID]
	if !exists || len(peerSessions) == 0 {
		return nil, 0, false
	}
	
	// Find the newest valid session key
	var newestKey *SessionKey
	var newestKeyID uint64
	
	for keyID, key := range peerSessions {
		if key.IsExpired() {
			continue
		}
		
		if newestKey == nil || key.ExpiresAt > newestKey.ExpiresAt {
			newestKey = key
			newestKeyID = keyID
		}
	}
	
	if newestKey != nil {
		return newestKey, newestKeyID, true
	}
	
	return nil, 0, false
}

// GetSessionKeyByID gets a session key by its ID
func (sm *SessionManager) GetSessionKeyByID(keyID uint64) (*SessionKey, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	key, found := sm.sessionsById[keyID]
	if !found || key.IsExpired() {
		return nil, false
	}
	
	return key, true
}

// ShouldRotateKey determines if it's time to rotate a key for a peer
func (sm *SessionManager) ShouldRotateKey(peerID string) bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	// Check if we have any sessions for this peer
	peerSessions, exists := sm.sessions[peerID]
	if !exists || len(peerSessions) == 0 {
		// No sessions, so we should create one
		return true
	}
	
	// Get the rotation count
	rotationCount, _ := sm.rotationCount[peerID]
	
	// If no rotation has happened yet, check the oldest key
	var oldestKey *SessionKey
	for _, key := range peerSessions {
		if !key.IsExpired() && (oldestKey == nil || key.ExpiresAt < oldestKey.ExpiresAt) {
			oldestKey = key
		}
	}
	
	if oldestKey == nil {
		// No valid keys, we should rotate
		return true
	}
	
	// Determine when this key should be rotated
	rotationTime := time.Unix(oldestKey.ExpiresAt, 0).Add(-sm.keyLifetime).Add(sm.rotationInterval * time.Duration(rotationCount))
	
	// If we've passed the rotation time, we should rotate
	return time.Now().After(rotationTime)
}

// RotateSessionKey creates a new session key for a peer
func (sm *SessionManager) RotateSessionKey(peerID string, keyGenerator func() ([]byte, error)) (uint64, error) {
	// Generate a new key
	newKey, err := keyGenerator()
	if err != nil {
		return 0, err
	}
	
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// Store the key
	keyID := sm.nextKeyID
	sm.nextKeyID++
	
	// Create a session key with expiration time
	sessionKey := &SessionKey{
		Key:       newKey,
		ExpiresAt: time.Now().Add(sm.keyLifetime).Unix(),
		PeerID:    peerID,
	}
	
	// Create the peer's session map if it doesn't exist
	if _, exists := sm.sessions[peerID]; !exists {
		sm.sessions[peerID] = make(map[uint64]*SessionKey)
	}
	
	// Store the key
	sm.sessions[peerID][keyID] = sessionKey
	sm.sessionsById[keyID] = sessionKey
	
	// Increment rotation count
	sm.rotationCount[peerID]++
	
	return keyID, nil
}

// GenerateRandomKey generates a random key for symmetric encryption
func GenerateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// CleanupExpiredKeys removes expired session keys
func (sm *SessionManager) CleanupExpiredKeys() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	now := time.Now().Unix()
	
	// Check all keys
	for peerID, peerSessions := range sm.sessions {
		for keyID, key := range peerSessions {
			if key.ExpiresAt < now {
				delete(peerSessions, keyID)
				delete(sm.sessionsById, keyID)
			}
		}
		
		// Remove peer entry if all keys are gone
		if len(peerSessions) == 0 {
			delete(sm.sessions, peerID)
			delete(sm.rotationCount, peerID)
		}
	}
} 