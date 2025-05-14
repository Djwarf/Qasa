package message

import (
	"sync"
	"time"
)

// RateLimitConfig defines limits for message sending
type RateLimitConfig struct {
	// Maximum number of messages per time window
	MaxMessages int

	// Duration of the time window
	TimeWindow time.Duration

	// Whether to allow bursts
	AllowBursts bool

	// Maximum messages for a burst
	BurstLimit int
}

// DefaultRateLimitConfig returns a reasonable default configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		MaxMessages: 60,          // 60 messages...
		TimeWindow:  time.Minute, // ...per minute (1 per second average)
		AllowBursts: true,
		BurstLimit:  10, // Allow up to 10 messages in quick succession
	}
}

// HighSecurityRateLimitConfig returns a stricter configuration
func HighSecurityRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		MaxMessages: 30,          // 30 messages...
		TimeWindow:  time.Minute, // ...per minute (0.5 per second average)
		AllowBursts: false,       // No bursts allowed
		BurstLimit:  0,
	}
}

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	config         *RateLimitConfig
	peerWindows    map[string][]time.Time // Map of peer ID to message timestamps
	peerBurstCount map[string]int         // Map of peer ID to current burst count
	mutex          sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	return &RateLimiter{
		config:         config,
		peerWindows:    make(map[string][]time.Time),
		peerBurstCount: make(map[string]int),
		mutex:          sync.Mutex{},
	}
}

// AllowMessage checks if a message is allowed based on rate limits
func (rl *RateLimiter) AllowMessage(peerID string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()

	// Get the time window for this peer
	window, exists := rl.peerWindows[peerID]
	if !exists {
		window = []time.Time{}
		rl.peerWindows[peerID] = window
	}

	// Remove timestamps outside the time window
	windowStart := now.Add(-rl.config.TimeWindow)
	newWindow := []time.Time{}

	for _, t := range window {
		if t.After(windowStart) {
			newWindow = append(newWindow, t)
		}
	}

	rl.peerWindows[peerID] = newWindow

	// Check if we've exceeded the limit
	if len(newWindow) >= rl.config.MaxMessages {
		return false
	}

	// Check for burst limiting
	if rl.config.AllowBursts {
		// Get or initialize burst count
		burstCount, exists := rl.peerBurstCount[peerID]
		if !exists {
			burstCount = 0
			rl.peerBurstCount[peerID] = burstCount
		}

		// Check for messages in quick succession (within 1 second)
		recentMessages := 0
		veryRecentWindow := now.Add(-1 * time.Second)

		for _, t := range newWindow {
			if t.After(veryRecentWindow) {
				recentMessages++
			}
		}

		// If messages are coming in quickly, count as part of a burst
		if recentMessages > 0 {
			burstCount++
			rl.peerBurstCount[peerID] = burstCount

			// If burst limit exceeded, reject the message
			if burstCount > rl.config.BurstLimit {
				return false
			}
		} else {
			// Reset burst count after a second of inactivity
			rl.peerBurstCount[peerID] = 0
		}
	}

	// Message is allowed, record its timestamp
	rl.peerWindows[peerID] = append(newWindow, now)

	return true
}

// GetRemainingMessages returns how many more messages are allowed in the current window
func (rl *RateLimiter) GetRemainingMessages(peerID string) int {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()

	// Get the time window for this peer
	window, exists := rl.peerWindows[peerID]
	if !exists {
		return rl.config.MaxMessages
	}

	// Remove timestamps outside the time window
	windowStart := now.Add(-rl.config.TimeWindow)
	newWindow := []time.Time{}

	for _, t := range window {
		if t.After(windowStart) {
			newWindow = append(newWindow, t)
		}
	}

	rl.peerWindows[peerID] = newWindow

	// Calculate remaining messages
	remaining := rl.config.MaxMessages - len(newWindow)
	if remaining < 0 {
		remaining = 0
	}

	return remaining
}

// ResetLimits clears all rate limits
func (rl *RateLimiter) ResetLimits() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.peerWindows = make(map[string][]time.Time)
	rl.peerBurstCount = make(map[string]int)
}
