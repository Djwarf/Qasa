package encryption

// CryptoProvider defines the interface that any crypto implementation
// must satisfy to be used with the QaSa network module
type CryptoProvider interface {
	// GenerateKeyPair generates a new key pair for the specified algorithm
	GenerateKeyPair(algorithm string) (KeyPair, error)

	// Encrypt encrypts plaintext for a recipient's public key
	Encrypt(plaintext []byte, recipientPublicKey []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the local private key
	Decrypt(ciphertext []byte, privateKey []byte) ([]byte, error)

	// Sign creates a signature for a message using the local private key
	Sign(message []byte, privateKey []byte) ([]byte, error)

	// Verify verifies a signature using the sender's public key
	Verify(message []byte, signature []byte, publicKey []byte) (bool, error)

	// DeriveSharedSecret derives a shared secret from a public key and private key
	DeriveSharedSecret(publicKey []byte, privateKey []byte) ([]byte, error)
}

// KeyPair represents a cryptographic key pair
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
	Algorithm  string
}

// Message represents an encrypted message in the QaSa network
type Message struct {
	// The encrypted message content
	Ciphertext []byte

	// The signature of the plaintext message
	Signature []byte

	// The sender's public key ID
	SenderID string

	// The recipient's public key ID
	RecipientID string

	// The timestamp when the message was created
	Timestamp int64

	// Algorithm identifiers
	EncryptionAlgorithm string
	SignatureAlgorithm  string
}

// SessionKey is defined in session_key.go
// SessionKey represents a temporary session key for efficient communication
//type SessionKey struct {
//	// The key used for encryption/decryption during the session
//	Key []byte
//
//	// When the session key expires
//	ExpiresAt int64
//
//	// The peer this session is established with
//	PeerID string
//}

// MessageType defines the type of message being exchanged
type MessageType int

const (
	// ChatMessage is a regular chat message
	ChatMessage MessageType = iota

	// KeyExchange is a message containing key exchange information
	KeyExchange

	// Handshake is a message for establishing a secure connection
	Handshake

	// KeepAlive is a message to maintain the connection
	KeepAlive
)

// EncryptionConfig holds the configuration for the encryption module
type EncryptionConfig struct {
	// The key encapsulation mechanism algorithm to use
	KEMAlgorithm string

	// The digital signature algorithm to use
	SigAlgorithm string

	// The symmetric encryption algorithm to use
	SymAlgorithm string

	// Whether to use perfect forward secrecy
	EnablePFS bool

	// How often to rotate session keys (in seconds)
	SessionKeyLifetime int64
}
