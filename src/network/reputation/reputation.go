package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// ReputationScoreFile is the file where reputation scores are stored
	ReputationScoreFile = "reputation_scores.json"

	// Default reputation values
	DefaultInitialScore    = 0
	DefaultMaxScore        = 100
	DefaultMinScore        = -100
	DefaultThresholdGood   = 50
	DefaultThresholdBad    = -50
	DefaultDecayTime       = 24 * time.Hour
	DefaultDecayPercentage = 0.1 // 10% decay
)

// ReputationStore stores and manages peer reputation data
type ReputationStore struct {
	Scores          map[string]*PeerScore `json:"scores"`
	configDir       string
	configPath      string
	mutex           sync.RWMutex
	maxScore        int
	minScore        int
	thresholdGood   int
	thresholdBad    int
	decayTime       time.Duration
	decayPercentage float64
}

func (rs *ReputationStore) Cleanup() error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	// Remove reputation data for peers that haven't been seen in a long time
	threshold := time.Now().Add(-30 * 24 * time.Hour) // 30 days

	for peerIDStr, peerScore := range rs.Scores {
		if peerScore.LastSeen.Before(threshold) {
			delete(rs.Scores, peerIDStr)
		}
	}

	return rs.Save()
}

// PeerScore represents a peer's reputation score and related metadata
type PeerScore struct {
	PeerID        string    `json:"peer_id"`
	Score         int       `json:"score"`
	LastUpdated   time.Time `json:"last_updated"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	GoodEvents    int       `json:"good_events"`
	NeutralEvents int       `json:"neutral_events"`
	BadEvents     int       `json:"bad_events"`
	Notes         string    `json:"notes,omitempty"`
}

// ReputationConfig defines configuration options for the reputation system
type ReputationConfig struct {
	MaxScore        int
	MinScore        int
	ThresholdGood   int
	ThresholdBad    int
	DecayTime       time.Duration
	DecayPercentage float64
}

// DefaultReputationConfig returns the default reputation system configuration
func DefaultReputationConfig() *ReputationConfig {
	return &ReputationConfig{
		MaxScore:        DefaultMaxScore,
		MinScore:        DefaultMinScore,
		ThresholdGood:   DefaultThresholdGood,
		ThresholdBad:    DefaultThresholdBad,
		DecayTime:       DefaultDecayTime,
		DecayPercentage: DefaultDecayPercentage,
	}
}

// NewReputationStore creates a new reputation store
func NewReputationStore(configDir string, config *ReputationConfig) (*ReputationStore, error) {
	if config == nil {
		config = DefaultReputationConfig()
	}

	rs := &ReputationStore{
		Scores:          make(map[string]*PeerScore),
		configDir:       configDir,
		maxScore:        config.MaxScore,
		minScore:        config.MinScore,
		thresholdGood:   config.ThresholdGood,
		thresholdBad:    config.ThresholdBad,
		decayTime:       config.DecayTime,
		decayPercentage: config.DecayPercentage,
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	rs.configPath = filepath.Join(configDir, ReputationScoreFile)

	// Try to load existing reputation data
	if err := rs.Load(); err != nil {
		// If file doesn't exist, initialize with defaults
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load reputation store: %w", err)
		}
		// This is a new store, save empty state
		if err := rs.Save(); err != nil {
			return nil, fmt.Errorf("failed to save initial reputation store: %w", err)
		}
	}

	return rs, nil
}

// Load loads reputation data from the configuration file
func (rs *ReputationStore) Load() error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	data, err := os.ReadFile(rs.configPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, rs)
}

// Save saves the reputation data to the configuration file
func (rs *ReputationStore) Save() error {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal reputation store: %w", err)
	}

	return os.WriteFile(rs.configPath, data, 0644)
}

// PeerStatus represents the reputation status of a peer
type PeerStatus string

const (
	// StatusUnknown means we don't have enough information about the peer
	StatusUnknown PeerStatus = "unknown"

	// StatusGood means the peer has a good reputation
	StatusGood PeerStatus = "good"

	// StatusNeutral means the peer has a neutral reputation
	StatusNeutral PeerStatus = "neutral"

	// StatusBad means the peer has a bad reputation
	StatusBad PeerStatus = "bad"
)

// EventType represents different types of reputation-affecting events
type EventType string

const (
	// EventMessageDelivered means a message was successfully delivered
	EventMessageDelivered EventType = "message_delivered"

	// EventMessageFailed means a message failed to deliver
	EventMessageFailed EventType = "message_failed"

	// EventKeyExchangeSuccessful means a key exchange was successful
	EventKeyExchangeSuccessful EventType = "key_exchange_successful"

	// EventKeyExchangeFailed means a key exchange failed
	EventKeyExchangeFailed EventType = "key_exchange_failed"

	// EventRateLimitExceeded means a peer exceeded rate limits
	EventRateLimitExceeded EventType = "rate_limit_exceeded"

	// EventInvalidMessage means a peer sent an invalid message
	EventInvalidMessage EventType = "invalid_message"

	// EventPeerConnected means a peer connected successfully
	EventPeerConnected EventType = "peer_connected"

	// EventPeerDisconnected means a peer disconnected
	EventPeerDisconnected EventType = "peer_disconnected"

	// EventManualBoost means the reputation was manually boosted
	EventManualBoost EventType = "manual_boost"

	// EventManualPenalty means the reputation was manually penalized
	EventManualPenalty EventType = "manual_penalty"
)

// EventScores defines the reputation score changes for different events
var EventScores = map[EventType]int{
	EventMessageDelivered:      1,
	EventMessageFailed:         -1,
	EventKeyExchangeSuccessful: 5,
	EventKeyExchangeFailed:     -5,
	EventRateLimitExceeded:     -10,
	EventInvalidMessage:        -15,
	EventPeerConnected:         2,
	EventPeerDisconnected:      0, // Neutral event
	EventManualBoost:           25,
	EventManualPenalty:         -25,
}

// GetPeerScore returns the reputation score for a peer
func (rs *ReputationStore) GetPeerScore(peerID peer.ID) int {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	peerIDStr := peerID.String()
	peerScore, exists := rs.Scores[peerIDStr]
	if !exists {
		return DefaultInitialScore
	}

	// Apply decay if needed
	if time.Since(peerScore.LastUpdated) > rs.decayTime {
		// Return the score without modifying the stored value
		// Actual decay happens in UpdateLastSeen or RecordEvent
		decayFactor := float64(time.Since(peerScore.LastUpdated)) / float64(rs.decayTime)
		decayAmount := int(float64(peerScore.Score) * rs.decayPercentage * decayFactor)

		// Decay toward zero
		if peerScore.Score > 0 {
			return max(0, peerScore.Score-decayAmount)
		} else if peerScore.Score < 0 {
			return min(0, peerScore.Score+decayAmount)
		}
	}

	return peerScore.Score
}

// GetPeerStatus returns the status of a peer based on its reputation
func (rs *ReputationStore) GetPeerStatus(peerID peer.ID) PeerStatus {
	score := rs.GetPeerScore(peerID)

	if score >= rs.thresholdGood {
		return StatusGood
	} else if score <= rs.thresholdBad {
		return StatusBad
	} else if score == DefaultInitialScore {
		return StatusUnknown
	}

	return StatusNeutral
}

// UpdateLastSeen updates the last seen time for a peer and decays score if needed
func (rs *ReputationStore) UpdateLastSeen(peerID peer.ID) error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	peerIDStr := peerID.String()
	now := time.Now()

	peerScore, exists := rs.Scores[peerIDStr]
	if !exists {
		// Create a new peer score entry
		rs.Scores[peerIDStr] = &PeerScore{
			PeerID:        peerIDStr,
			Score:         DefaultInitialScore,
			LastUpdated:   now,
			FirstSeen:     now,
			LastSeen:      now,
			GoodEvents:    0,
			NeutralEvents: 0,
			BadEvents:     0,
		}
	} else {
		// Update the last seen time
		peerScore.LastSeen = now

		// Apply decay if needed
		if time.Since(peerScore.LastUpdated) > rs.decayTime {
			decayFactor := float64(time.Since(peerScore.LastUpdated)) / float64(rs.decayTime)
			decayAmount := int(float64(peerScore.Score) * rs.decayPercentage * decayFactor)

			// Decay toward zero
			if peerScore.Score > 0 {
				peerScore.Score = max(0, peerScore.Score-decayAmount)
			} else if peerScore.Score < 0 {
				peerScore.Score = min(0, peerScore.Score+decayAmount)
			}

			peerScore.LastUpdated = now
		}
	}

	return rs.Save()
}

// RecordEvent records a reputation-affecting event for a peer
func (rs *ReputationStore) RecordEvent(peerID peer.ID, event EventType) error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	peerIDStr := peerID.String()
	now := time.Now()

	// Get the score change for this event
	scoreChange, exists := EventScores[event]
	if !exists {
		return fmt.Errorf("unknown event type: %s", event)
	}

	peerScore, exists := rs.Scores[peerIDStr]
	if !exists {
		// Create a new peer score entry
		peerScore = &PeerScore{
			PeerID:        peerIDStr,
			Score:         DefaultInitialScore,
			LastUpdated:   now,
			FirstSeen:     now,
			LastSeen:      now,
			GoodEvents:    0,
			NeutralEvents: 0,
			BadEvents:     0,
		}
		rs.Scores[peerIDStr] = peerScore
	}

	// Apply decay if needed
	if time.Since(peerScore.LastUpdated) > rs.decayTime {
		decayFactor := float64(time.Since(peerScore.LastUpdated)) / float64(rs.decayTime)
		decayAmount := int(float64(peerScore.Score) * rs.decayPercentage * decayFactor)

		// Decay toward zero
		if peerScore.Score > 0 {
			peerScore.Score = max(0, peerScore.Score-decayAmount)
		} else if peerScore.Score < 0 {
			peerScore.Score = min(0, peerScore.Score+decayAmount)
		}
	}

	// Update the score
	peerScore.Score += scoreChange

	// Ensure the score stays within bounds
	if peerScore.Score > rs.maxScore {
		peerScore.Score = rs.maxScore
	} else if peerScore.Score < rs.minScore {
		peerScore.Score = rs.minScore
	}

	// Update event counters
	if scoreChange > 0 {
		peerScore.GoodEvents++
	} else if scoreChange < 0 {
		peerScore.BadEvents++
	} else {
		peerScore.NeutralEvents++
	}

	// Update timestamps
	peerScore.LastUpdated = now
	peerScore.LastSeen = now

	return rs.Save()
}

// GetBadPeers returns a list of peers with bad reputation
func (rs *ReputationStore) GetBadPeers() []peer.ID {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	var badPeers []peer.ID

	for peerIDStr, peerScore := range rs.Scores {
		if peerScore.Score <= rs.thresholdBad {
			peerID, err := peer.Decode(peerIDStr)
			if err == nil {
				badPeers = append(badPeers, peerID)
			}
		}
	}

	return badPeers
}

// GetGoodPeers returns a list of peers with good reputation
func (rs *ReputationStore) GetGoodPeers() []peer.ID {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	var goodPeers []peer.ID

	for peerIDStr, peerScore := range rs.Scores {
		if peerScore.Score >= rs.thresholdGood {
			peerID, err := peer.Decode(peerIDStr)
			if err == nil {
				goodPeers = append(goodPeers, peerID)
			}
		}
	}

	return goodPeers
}

// AddNote adds a note to a peer's reputation record
func (rs *ReputationStore) AddNote(peerID peer.ID, note string) error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	peerIDStr := peerID.String()

	peerScore, exists := rs.Scores[peerIDStr]
	if !exists {
		// Create a new peer score entry
		now := time.Now()
		peerScore = &PeerScore{
			PeerID:        peerIDStr,
			Score:         DefaultInitialScore,
			LastUpdated:   now,
			FirstSeen:     now,
			LastSeen:      now,
			GoodEvents:    0,
			NeutralEvents: 0,
			BadEvents:     0,
		}
		rs.Scores[peerIDStr] = peerScore
	}

	peerScore.Notes = note

	return rs.Save()
}

// ResetPeerScore resets a peer's reputation to the initial score
func (rs *ReputationStore) ResetPeerScore(peerID peer.ID) error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	peerIDStr := peerID.String()

	peerScore, exists := rs.Scores[peerIDStr]
	if !exists {
		return nil // Nothing to reset
	}

	now := time.Now()
	peerScore.Score = DefaultInitialScore
	peerScore.LastUpdated = now
	peerScore.GoodEvents = 0
	peerScore.NeutralEvents = 0
	peerScore.BadEvents = 0

	return rs.Save()
}

// RemovePeer removes a peer from the reputation store
func (rs *ReputationStore) RemovePeer(peerID peer.ID) error {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	delete(rs.Scores, peerID.String())

	return rs.Save()
}

// StartCleanupRoutine starts a goroutine to periodically clean up old reputation data
func (rs *ReputationStore) StartCleanupRoutine(ctx context.Context, cleanupInterval time.Duration) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				rs.cleanupOldData()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// cleanupOldData removes reputation data for peers that haven't been seen in a long time
func (rs *ReputationStore) cleanupOldData() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	threshold := time.Now().Add(-30 * 24 * time.Hour) // 30 days

	for peerIDStr, peerScore := range rs.Scores {
		if peerScore.LastSeen.Before(threshold) {
			delete(rs.Scores, peerIDStr)
		}
	}

	rs.Save()
}

// GetPeersWithScoreBelowThreshold returns peers with scores below the given threshold
func (rs *ReputationStore) GetPeersWithScoreBelowThreshold(threshold int) []peer.ID {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()

	var lowScorePeers []peer.ID

	for peerIDStr, peerScore := range rs.Scores {
		if peerScore.Score <= threshold {
			peerID, err := peer.Decode(peerIDStr)
			if err == nil {
				lowScorePeers = append(lowScorePeers, peerID)
			}
		}
	}

	return lowScorePeers
}
