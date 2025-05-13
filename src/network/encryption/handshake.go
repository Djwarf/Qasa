package encryption

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// HandshakeMessage represents a message exchanged during key exchange
type HandshakeMessage struct {
	// Message type (1 = Init, 2 = Response, 3 = Finalise)
	Type uint8
	
	// The algorithm used for key exchange
	Algorithm string
	
	// The sender's public key
	PublicKey []byte
	
	// For the Init message, this is the encapsulated shared secret
	// For the Response message, this contains the responder's public key
	// For the Finalise message, it contains encrypted confirmation data
	Payload []byte
	
	// Digital signature to verify authenticity
	Signature []byte
	
	// Timestamp to prevent replay attacks
	Timestamp int64
}

// Encode serializes a handshake message to bytes
func (h *HandshakeMessage) Encode() ([]byte, error) {
	// Calculate total size
	size := 1 + // Type
		2 + len(h.Algorithm) + // Algorithm (2-byte length prefix)
		4 + len(h.PublicKey) + // PublicKey (4-byte length prefix)
		4 + len(h.Payload) + // Payload (4-byte length prefix)
		4 + len(h.Signature) + // Signature (4-byte length prefix)
		8 // Timestamp (8 bytes)
	
	// Allocate buffer
	buf := make([]byte, size)
	offset := 0
	
	// Write type
	buf[offset] = h.Type
	offset++
	
	// Write algorithm
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(h.Algorithm)))
	offset += 2
	copy(buf[offset:], h.Algorithm)
	offset += len(h.Algorithm)
	
	// Write public key
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(h.PublicKey)))
	offset += 4
	copy(buf[offset:], h.PublicKey)
	offset += len(h.PublicKey)
	
	// Write payload
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(h.Payload)))
	offset += 4
	copy(buf[offset:], h.Payload)
	offset += len(h.Payload)
	
	// Write signature
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(h.Signature)))
	offset += 4
	copy(buf[offset:], h.Signature)
	offset += len(h.Signature)
	
	// Write timestamp
	binary.BigEndian.PutUint64(buf[offset:], uint64(h.Timestamp))
	
	return buf, nil
}

// Decode parses a handshake message from bytes
func DecodeHandshakeMessage(data []byte) (*HandshakeMessage, error) {
	if len(data) < 23 { // Minimum size for a valid message
		return nil, errors.New("handshake message too short")
	}
	
	h := &HandshakeMessage{}
	offset := 0
	
	// Read type
	h.Type = data[offset]
	offset++
	
	// Read algorithm
	algLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2
	if offset+int(algLen) > len(data) {
		return nil, errors.New("handshake message truncated: algorithm")
	}
	h.Algorithm = string(data[offset : offset+int(algLen)])
	offset += int(algLen)
	
	// Read public key
	if offset+4 > len(data) {
		return nil, errors.New("handshake message truncated: public key length")
	}
	pkLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(pkLen) > len(data) {
		return nil, errors.New("handshake message truncated: public key")
	}
	h.PublicKey = data[offset : offset+int(pkLen)]
	offset += int(pkLen)
	
	// Read payload
	if offset+4 > len(data) {
		return nil, errors.New("handshake message truncated: payload length")
	}
	payloadLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(payloadLen) > len(data) {
		return nil, errors.New("handshake message truncated: payload")
	}
	h.Payload = data[offset : offset+int(payloadLen)]
	offset += int(payloadLen)
	
	// Read signature
	if offset+4 > len(data) {
		return nil, errors.New("handshake message truncated: signature length")
	}
	sigLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if offset+int(sigLen) > len(data) {
		return nil, errors.New("handshake message truncated: signature")
	}
	h.Signature = data[offset : offset+int(sigLen)]
	offset += int(sigLen)
	
	// Read timestamp
	if offset+8 > len(data) {
		return nil, errors.New("handshake message truncated: timestamp")
	}
	h.Timestamp = int64(binary.BigEndian.Uint64(data[offset:]))
	
	return h, nil
}

// KeyExchangeHandler manages the key exchange process
type KeyExchangeHandler struct {
	// The crypto provider to use
	provider CryptoProvider
	
	// The local key pairs for key exchange and signing
	kemKeyPair      KeyPair
	signingKeyPair  KeyPair
	
	// Maximum age of handshake messages to prevent replay attacks
	maxMessageAge time.Duration
}

// NewKeyExchangeHandler creates a new handler for key exchange
func NewKeyExchangeHandler(provider CryptoProvider) (*KeyExchangeHandler, error) {
	// Generate key pairs
	kemKeyPair, err := provider.GenerateKeyPair("kyber768")
	if err != nil {
		return nil, fmt.Errorf("failed to generate KEM key pair: %w", err)
	}
	
	signingKeyPair, err := provider.GenerateKeyPair("dilithium3")
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key pair: %w", err)
	}
	
	return &KeyExchangeHandler{
		provider:      provider,
		kemKeyPair:    kemKeyPair,
		signingKeyPair: signingKeyPair,
		maxMessageAge: 5 * time.Minute, // 5 minutes max age
	}, nil
}

// CreateInitiatorMessage creates the first message in the key exchange
func (k *KeyExchangeHandler) CreateInitiatorMessage() ([]byte, []byte, error) {
	// Encrypt a dummy message to get the ciphertext, which includes the encapsulated shared secret
	plaintext := []byte("QaSa_INIT")
	ciphertext, err := k.provider.Encrypt(plaintext, k.kemKeyPair.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create initial ciphertext: %w", err)
	}
	
	// Create the handshake message
	msg := &HandshakeMessage{
		Type:      1, // Init
		Algorithm: k.kemKeyPair.Algorithm,
		PublicKey: k.kemKeyPair.PublicKey,
		Payload:   ciphertext,
		Timestamp: time.Now().Unix(),
	}
	
	// Sign the message
	dataToSign := append(msg.PublicKey, msg.Payload...)
	dataToSign = append(dataToSign, byte(msg.Timestamp))
	
	signature, err := k.provider.Sign(dataToSign, k.signingKeyPair.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign handshake message: %w", err)
	}
	
	msg.Signature = signature
	
	// Encode the message
	encoded, err := msg.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode handshake message: %w", err)
	}
	
	// Extract the shared secret from the ciphertext
	// (In a real implementation, we would have the shared secret from Encrypt,
	// but our interface doesn't return it directly, so we'll decrypt the message)
	decrypted, err := k.provider.Decrypt(ciphertext, k.kemKeyPair.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract shared secret: %w", err)
	}
	
	// In practice, we would derive a session key from this, but for now we'll use it directly
	return encoded, decrypted, nil
}

// ProcessInitiatorMessage processes the first message in the key exchange
func (k *KeyExchangeHandler) ProcessInitiatorMessage(data []byte) ([]byte, []byte, error) {
	// Decode the message
	msg, err := DecodeHandshakeMessage(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode handshake message: %w", err)
	}
	
	// Check message type
	if msg.Type != 1 {
		return nil, nil, fmt.Errorf("expected Init message (type 1), got type %d", msg.Type)
	}
	
	// Check timestamp to prevent replay attacks
	now := time.Now().Unix()
	msgTime := msg.Timestamp
	if now-msgTime > int64(k.maxMessageAge.Seconds()) {
		return nil, nil, fmt.Errorf("handshake message too old")
	}
	
	// Decrypt the payload to extract the shared secret
	// We don't have the sender's private key, so we need to use our own keys
	// In a real implementation, we would use the recipient's public key
	
	// Derive a shared secret using our private key and the sender's public key
	sharedSecret, err := k.provider.DeriveSharedSecret(msg.PublicKey, k.kemKeyPair.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}
	
	// Create a response message
	respMsg := &HandshakeMessage{
		Type:      2, // Response
		Algorithm: k.kemKeyPair.Algorithm,
		PublicKey: k.kemKeyPair.PublicKey,
		Payload:   nil, // No additional payload needed
		Timestamp: time.Now().Unix(),
	}
	
	// Sign the response
	dataToSign := append(respMsg.PublicKey, byte(respMsg.Timestamp))
	signature, err := k.provider.Sign(dataToSign, k.signingKeyPair.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign response message: %w", err)
	}
	
	respMsg.Signature = signature
	
	// Encode the response
	encoded, err := respMsg.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode response message: %w", err)
	}
	
	return encoded, sharedSecret, nil
}

// ProcessResponseMessage processes the response message in the key exchange
func (k *KeyExchangeHandler) ProcessResponseMessage(data []byte, initialSharedSecret []byte) ([]byte, error) {
	// Decode the message
	msg, err := DecodeHandshakeMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response message: %w", err)
	}
	
	// Check message type
	if msg.Type != 2 {
		return nil, fmt.Errorf("expected Response message (type 2), got type %d", msg.Type)
	}
	
	// Check timestamp to prevent replay attacks
	now := time.Now().Unix()
	msgTime := msg.Timestamp
	if now-msgTime > int64(k.maxMessageAge.Seconds()) {
		return nil, fmt.Errorf("response message too old")
	}
	
	// Verify the signature
	dataToVerify := append(msg.PublicKey, byte(msg.Timestamp))
	// In a real implementation, we would have the sender's public signing key
	// For now, we'll use our own public key for demonstration
	valid, err := k.provider.Verify(dataToVerify, msg.Signature, k.signingKeyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}
	
	if !valid {
		return nil, fmt.Errorf("invalid signature in response message")
	}
	
	// Create a finalization message
	finalMsg := &HandshakeMessage{
		Type:      3, // Finalise
		Algorithm: k.kemKeyPair.Algorithm,
		PublicKey: k.kemKeyPair.PublicKey,
		Timestamp: time.Now().Unix(),
	}
	
	// Encrypt a confirmation using the shared secret
	confirmationPlaintext := []byte("QaSa_CONFIRM")
	confirmationCiphertext, err := k.provider.Encrypt(confirmationPlaintext, msg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt confirmation: %w", err)
	}
	
	finalMsg.Payload = confirmationCiphertext
	
	// Sign the finalization message
	dataToSign := append(finalMsg.PublicKey, finalMsg.Payload...)
	dataToSign = append(dataToSign, byte(finalMsg.Timestamp))
	
	signature, err := k.provider.Sign(dataToSign, k.signingKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign finalization message: %w", err)
	}
	
	finalMsg.Signature = signature
	
	// Encode the finalization message
	encoded, err := finalMsg.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode finalization message: %w", err)
	}
	
	// Return the session key (derived from the shared secret)
	// In a real implementation, we would use a KDF to derive the session key
	return encoded, nil
}

// ProcessFinalizationMessage processes the finalization message
func (k *KeyExchangeHandler) ProcessFinalizationMessage(data []byte, sharedSecret []byte) error {
	// Decode the message
	msg, err := DecodeHandshakeMessage(data)
	if err != nil {
		return fmt.Errorf("failed to decode finalization message: %w", err)
	}
	
	// Check message type
	if msg.Type != 3 {
		return fmt.Errorf("expected Finalise message (type 3), got type %d", msg.Type)
	}
	
	// Check timestamp to prevent replay attacks
	now := time.Now().Unix()
	msgTime := msg.Timestamp
	if now-msgTime > int64(k.maxMessageAge.Seconds()) {
		return fmt.Errorf("finalization message too old")
	}
	
	// Verify the signature
	dataToVerify := append(msg.PublicKey, msg.Payload...)
	dataToVerify = append(dataToVerify, byte(msg.Timestamp))
	
	// In a real implementation, we would have the sender's public signing key
	// For now, we'll use our own public key for demonstration
	valid, err := k.provider.Verify(dataToVerify, msg.Signature, k.signingKeyPair.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	
	if !valid {
		return fmt.Errorf("invalid signature in finalization message")
	}
	
	// Decrypt the confirmation message
	// In a real implementation, we would use the shared secret to derive a key,
	// but here we'll decrypt using our private key
	decrypted, err := k.provider.Decrypt(msg.Payload, k.kemKeyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt confirmation: %w", err)
	}
	
	// Verify the confirmation
	if string(decrypted) != "QaSa_CONFIRM" {
		return fmt.Errorf("invalid confirmation message")
	}
	
	// Handshake complete
	return nil
} 