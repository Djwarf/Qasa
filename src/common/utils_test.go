package common

import (
	"testing"
	"time"
	
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestGenerateID(t *testing.T) {
	id1 := GenerateID()
	id2 := GenerateID()
	
	if id1 == id2 {
		t.Error("GenerateID should produce unique IDs")
	}
	
	if len(id1) != 32 { // 16 bytes * 2 hex chars
		t.Errorf("Expected ID length 32, got %d", len(id1))
	}
}

func TestGenerateMessageID(t *testing.T) {
	msgID1 := GenerateMessageID()
	time.Sleep(1 * time.Millisecond) // Ensure different timestamp
	msgID2 := GenerateMessageID()
	
	if msgID1 == msgID2 {
		t.Error("GenerateMessageID should produce unique IDs")
	}
}

func TestBytesEqual(t *testing.T) {
	tests := []struct {
		a, b     []byte
		expected bool
	}{
		{[]byte("hello"), []byte("hello"), true},
		{[]byte("hello"), []byte("world"), false},
		{[]byte{}, []byte{}, true},
		{[]byte("a"), []byte{}, false},
		{nil, nil, true},
		{[]byte("test"), nil, false},
	}
	
	for _, test := range tests {
		result := BytesEqual(test.a, test.b)
		if result != test.expected {
			t.Errorf("BytesEqual(%v, %v) = %v, want %v", test.a, test.b, result, test.expected)
		}
	}
}

func TestShortenPeerID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"short", "short"},
		{"verylongpeeridthatshouldbeshortened", "verylongpeeridthatshouldbeshortened"[:8] + "..."},
		{"exactly12ch", "exactly12ch"},
		{"exactlymorethan12chars", "exactlym..."},
	}
	
	for _, test := range tests {
		result := ShortenPeerID(test.input)
		if result != test.expected {
			t.Errorf("ShortenPeerID(%q) = %q, want %q", test.input, result, test.expected)
		}
	}
}

func TestIsValidPeerID(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"QmNLei78zWmzUdbeRB3CiUfAizWUrbeeZh5K1rhAQKCh51", true}, // Real libp2p peer ID
		{"", false},
		{"short", false},
		{"invalid-chars!", false},
		{"12D3KooWGDMwwqrpcYKpKCgxuKT2NfqPqa94QnkoBBpqvCaiCzWd", true}, // Another valid format
	}
	
	for _, test := range tests {
		result := IsValidPeerID(test.input)
		if result != test.expected {
			t.Errorf("IsValidPeerID(%q) = %v, want %v", test.input, result, test.expected)
		}
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	
	tests := []struct {
		timestamp time.Time
		duration  time.Duration
		expected  bool
	}{
		{past, 30 * time.Minute, true},
		{past, 2 * time.Hour, false},
		{future, 30 * time.Minute, false},
		{now.Add(-1 * time.Second), 0, true}, // Fixed: 0 duration means always expired
	}
	
	for _, test := range tests {
		result := IsExpired(test.timestamp, test.duration)
		if result != test.expected {
			t.Errorf("IsExpired(%v, %v) = %v, want %v", test.timestamp, test.duration, result, test.expected)
		}
	}
}

func TestMinMaxClamp(t *testing.T) {
	// Test MinInt
	if MinInt(5, 3) != 3 {
		t.Error("MinInt(5, 3) should return 3")
	}
	
	// Test MaxInt
	if MaxInt(5, 3) != 5 {
		t.Error("MaxInt(5, 3) should return 5")
	}
	
	// Test ClampInt
	tests := []struct {
		value, min, max, expected int
	}{
		{5, 1, 10, 5},   // within range
		{0, 1, 10, 1},   // below min
		{15, 1, 10, 10}, // above max
		{5, 5, 5, 5},    // exact match
	}
	
	for _, test := range tests {
		result := ClampInt(test.value, test.min, test.max)
		if result != test.expected {
			t.Errorf("ClampInt(%d, %d, %d) = %d, want %d", 
				test.value, test.min, test.max, result, test.expected)
		}
	}
}

func TestSafeContains(t *testing.T) {
	tests := []struct {
		str, substr string
		expected    bool
	}{
		{"hello world", "world", true},
		{"hello world", "WORLD", true}, // case insensitive
		{"hello world", "xyz", false},
		{"", "test", false},
		{"test", "", false},
		{"Test", "est", true},
	}
	
	for _, test := range tests {
		result := SafeContains(test.str, test.substr)
		if result != test.expected {
			t.Errorf("SafeContains(%q, %q) = %v, want %v", 
				test.str, test.substr, result, test.expected)
		}
	}
}

// Mock peer IDs for testing
func mockPeerID(s string) peer.ID {
	// This is a simplified mock - in real tests you'd use proper peer ID generation
	// For now, we'll just test the string representation
	id, _ := peer.Decode("QmSomeValidPeerID" + s)
	return id
}

func TestPeerListsEqual(t *testing.T) {
	// Create mock peer IDs (simplified for testing)
	peer1, _ := peer.Decode("QmPeer1111111111111111111111111111111111111111")
	peer2, _ := peer.Decode("QmPeer2222222222222222222222222222222222222222") 
	peer3, _ := peer.Decode("QmPeer3333333333333333333333333333333333333333")
	
	tests := []struct {
		a, b     []peer.ID
		expected bool
	}{
		{[]peer.ID{}, []peer.ID{}, true},
		{[]peer.ID{peer1}, []peer.ID{peer1}, true},
		{[]peer.ID{peer1, peer2}, []peer.ID{peer2, peer1}, true}, // order doesn't matter
		{[]peer.ID{peer1}, []peer.ID{peer2}, false},
		{[]peer.ID{peer1}, []peer.ID{}, false},
		{[]peer.ID{peer1, peer2}, []peer.ID{peer1, peer2, peer3}, false},
	}
	
	for _, test := range tests {
		result := PeerListsEqual(test.a, test.b)
		if result != test.expected {
			t.Errorf("PeerListsEqual() = %v, want %v", result, test.expected)
		}
	}
} 