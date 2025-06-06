package common

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
	
	"github.com/libp2p/go-libp2p/core/peer"
)

// ID generation utilities

// GenerateID generates a unique identifier using crypto/rand
func GenerateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateMessageID generates a unique ID for a message with timestamp
func GenerateMessageID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), GenerateShortID())
}

// GenerateShortID generates a shorter unique identifier
func GenerateShortID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Comparison utilities

// BytesEqual compares two byte slices for equality in constant time
func BytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// PeerListsEqual compares two peer ID lists for equality
func PeerListsEqual(a, b []peer.ID) bool {
	if len(a) != len(b) {
		return false
	}
	
	aMap := make(map[string]bool)
	for _, p := range a {
		aMap[p.String()] = true
	}
	
	for _, p := range b {
		if !aMap[p.String()] {
			return false
		}
	}
	
	return true
}

// String utilities

// ShortenPeerID shortens a peer ID for display
func ShortenPeerID(peerID string) string {
	if len(peerID) <= 12 {
		return peerID
	}
	return peerID[:8] + "..."
}

// GetDisplayName returns a display name for a peer ID with fallback
func GetDisplayName(peerID string, profiles map[string]interface{}) string {
	if profile, exists := profiles[peerID]; exists {
		if profileMap, ok := profile.(map[string]interface{}); ok {
			if displayName, ok := profileMap["display_name"].(string); ok && displayName != "" {
				return displayName
			}
		}
	}
	return fmt.Sprintf("User-%s", ShortenPeerID(peerID))
}

// Time utilities

// IsExpired checks if a timestamp has passed the given duration
func IsExpired(timestamp time.Time, duration time.Duration) bool {
	return time.Since(timestamp) > duration
}

// GetTimeAgo returns a human-readable "time ago" string
func GetTimeAgo(timestamp time.Time) string {
	duration := time.Since(timestamp)
	if duration < time.Minute {
		return "just now"
	} else if duration < time.Hour {
		minutes := int(duration.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	} else if duration < 24*time.Hour {
		hours := int(duration.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	} else {
		days := int(duration.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

// Validation utilities

// IsValidPeerID checks if a string is a valid peer ID
func IsValidPeerID(peerIDStr string) bool {
	_, err := peer.Decode(peerIDStr)
	return err == nil
}

// SafeContains checks if a string contains a substring safely (case-insensitive)
func SafeContains(str, substr string) bool {
	if str == "" || substr == "" {
		return false
	}
	// Simple case-insensitive contains check
	return len(str) >= len(substr) && 
		   containsIgnoreCase(str, substr)
}

func containsIgnoreCase(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if toLowerCase(str[i+j]) != toLowerCase(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func toLowerCase(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// Math utilities

// MinInt returns the minimum of two integers
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MaxInt returns the maximum of two integers
func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ClampInt clamps an integer between min and max values
func ClampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
} 