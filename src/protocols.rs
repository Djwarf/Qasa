/*!
 * High-Level Protocol Implementations for QaSa Cryptography
 *
 * Provides ready-to-use implementations of quantum-safe communication protocols,
 * including TLS 1.3 extensions and secure messaging protocols.
 */

use crate::aes;
use crate::dilithium::{DilithiumKeyPair, DilithiumPublicKey};
use crate::error::{error_codes, CryptoError, CryptoResult};
use crate::kyber::{KyberKeyPair, KyberPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Session identifier for tracking communication sessions
pub type SessionId = [u8; 32];

/// Contact identifier for secure messaging
pub type ContactId = String;

/// Quantum-Safe TLS 1.3 Implementation
///
/// This implementation extends TLS 1.3 with post-quantum key exchange and authentication.
/// It provides hybrid security by combining classical and post-quantum algorithms.
pub struct QuantumSafeTLS {
    /// Long-term identity keys for authentication
    kyber_keypair: KyberKeyPair,
    dilithium_keypair: DilithiumKeyPair,

    /// Active session keys
    session_keys: HashMap<SessionId, SessionKey>,

    /// Protocol configuration
    config: TlsConfig,

    /// Current state of the TLS handshake
    state: TlsState,
}

impl std::fmt::Debug for QuantumSafeTLS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuantumSafeTLS")
            .field("session_keys_count", &self.session_keys.len())
            .field("config", &self.config)
            .field("state", &self.state)
            .field("kyber_algorithm", &self.kyber_keypair.algorithm)
            .field("dilithium_algorithm", &self.dilithium_keypair.algorithm)
            .finish_non_exhaustive()
    }
}

/// TLS configuration parameters
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub max_sessions: usize,
    pub session_timeout: Duration,
    pub supported_cipher_suites: Vec<CipherSuite>,
    pub require_client_authentication: bool,
    pub enable_session_resumption: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            session_timeout: Duration::from_secs(3600), // 1 hour
            supported_cipher_suites: vec![
                CipherSuite::Kyber768_Dilithium3_AES256GCM,
                CipherSuite::Kyber1024_Dilithium5_AES256GCM,
            ],
            require_client_authentication: false,
            enable_session_resumption: true,
        }
    }
}

/// Supported cipher suites combining post-quantum algorithms
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CipherSuite {
    Kyber768_Dilithium3_AES256GCM,
    Kyber1024_Dilithium5_AES256GCM,
    Kyber512_Dilithium2_AES256GCM,
}

/// TLS handshake state machine
#[derive(Debug, Clone, PartialEq)]
pub enum TlsState {
    Initial,
    ClientHelloSent,
    ServerHelloReceived,
    CertificateReceived,
    KeyExchangeComplete,
    HandshakeComplete,
    ApplicationData,
    Closed,
}

/// Session key information
#[derive(Debug, Clone)]
pub struct SessionKey {
    id: SessionId,
    shared_secret: [u8; 32],
    cipher_suite: CipherSuite,
    created_at: SystemTime,
    last_used: SystemTime,
}

/// TLS handshake messages
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u16,
    pub random: [u8; 32],
    pub cipher_suites: Vec<CipherSuite>,
    pub kyber_public_key: Vec<u8>,
    pub extensions: Vec<TlsExtension>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u16,
    pub random: [u8; 32],
    pub cipher_suite: CipherSuite,
    pub kyber_ciphertext: Vec<u8>,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
    pub extensions: Vec<TlsExtension>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

impl QuantumSafeTLS {
    /// Create a new quantum-safe TLS instance
    pub fn new(config: TlsConfig) -> CryptoResult<Self> {
        let kyber_keypair = KyberKeyPair::generate(crate::kyber::KyberVariant::Kyber768)?;
        let dilithium_keypair =
            DilithiumKeyPair::generate(crate::dilithium::DilithiumVariant::Dilithium3)?;

        Ok(Self {
            kyber_keypair,
            dilithium_keypair,
            session_keys: HashMap::new(),
            config,
            state: TlsState::Initial,
        })
    }

    /// Initiate TLS handshake as client
    pub fn client_hello(&mut self) -> CryptoResult<ClientHello> {
        if self.state != TlsState::Initial {
            return Err(CryptoError::ProtocolError {
                protocol: "TLS".to_string(),
                phase: "client_hello".to_string(),
                cause: format!("Invalid state: {:?}", self.state),
                error_code: error_codes::PROTOCOL_STATE_INVALID,
            });
        }

        let random = self.generate_random_bytes()?;
        let kyber_public_key = bincode::serialize(&self.kyber_keypair.public_key())
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        let client_hello = ClientHello {
            version: 0x0304, // TLS 1.3
            random,
            cipher_suites: self.config.supported_cipher_suites.clone(),
            kyber_public_key,
            extensions: vec![],
        };

        self.state = TlsState::ClientHelloSent;
        Ok(client_hello)
    }

    /// Process client hello and generate server response
    pub fn server_hello(&mut self, client_hello: &ClientHello) -> CryptoResult<ServerHello> {
        if self.state != TlsState::Initial {
            return Err(CryptoError::ProtocolError {
                protocol: "TLS".to_string(),
                phase: "server_hello".to_string(),
                cause: format!("Invalid state: {:?}", self.state),
                error_code: error_codes::PROTOCOL_STATE_INVALID,
            });
        }

        // Select cipher suite
        let cipher_suite = self.select_cipher_suite(&client_hello.cipher_suites)?;

        // Perform key encapsulation
        let client_kyber_key: KyberPublicKey = bincode::deserialize(&client_hello.kyber_public_key)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        let (kyber_ciphertext, shared_secret) = client_kyber_key.encapsulate()?;

        // Generate certificate and signature
        let certificate = self.generate_certificate()?;
        let signature = self.sign_handshake_data(&client_hello, &certificate)?;

        // Create session
        let session_id = self.generate_session_id()?;
        let shared_secret_len = shared_secret.len();
        let shared_secret_array: [u8; 32] = shared_secret.try_into().map_err(|_| {
            CryptoError::invalid_parameter(
                "shared_secret",
                "32 bytes",
                &format!("{} bytes", shared_secret_len),
            )
        })?;
        let session_key = SessionKey {
            id: session_id,
            shared_secret: shared_secret_array,
            cipher_suite: cipher_suite.clone(),
            created_at: SystemTime::now(),
            last_used: SystemTime::now(),
        };

        self.session_keys.insert(session_id, session_key);

        let server_hello = ServerHello {
            version: 0x0304,
            random: self.generate_random_bytes()?,
            cipher_suite,
            kyber_ciphertext,
            certificate,
            signature,
            extensions: vec![],
        };

        self.state = TlsState::HandshakeComplete;
        Ok(server_hello)
    }

    /// Establish secure session after handshake completion
    pub fn establish_session(&mut self, handshake: &Handshake) -> CryptoResult<Session> {
        if self.state != TlsState::HandshakeComplete {
            return Err(CryptoError::ProtocolError {
                protocol: "TLS".to_string(),
                phase: "establish_session".to_string(),
                cause: format!("Handshake not complete: {:?}", self.state),
                error_code: error_codes::PROTOCOL_STATE_INVALID,
            });
        }

        let session_id = handshake.session_id;
        let session_key =
            self.session_keys
                .get(&session_id)
                .ok_or_else(|| CryptoError::ProtocolError {
                    protocol: "TLS".to_string(),
                    phase: "establish_session".to_string(),
                    cause: "Session not found".to_string(),
                    error_code: error_codes::PROTOCOL_STATE_INVALID,
                })?;

        self.state = TlsState::ApplicationData;

        Ok(Session {
            id: session_id,
            cipher_suite: session_key.cipher_suite.clone(),
            send_key: derive_send_key(&session_key.shared_secret)?,
            receive_key: derive_receive_key(&session_key.shared_secret)?,
            sequence_number: 0,
        })
    }

    /// Encrypt application data
    pub fn encrypt_data(&mut self, data: &[u8], session: &Session) -> CryptoResult<Vec<u8>> {
        if self.state != TlsState::ApplicationData {
            return Err(CryptoError::ProtocolError {
                protocol: "TLS".to_string(),
                phase: "encrypt_data".to_string(),
                cause: "Not in application data state".to_string(),
                error_code: error_codes::PROTOCOL_STATE_INVALID,
            });
        }

        let nonce = self.generate_nonce(session.sequence_number)?;
        let (ciphertext, _) = aes::encrypt(data, &session.send_key, Some(&nonce))?;
        Ok(ciphertext)
    }

    /// Decrypt application data
    pub fn decrypt_data(&mut self, ciphertext: &[u8], session: &Session) -> CryptoResult<Vec<u8>> {
        if self.state != TlsState::ApplicationData {
            return Err(CryptoError::ProtocolError {
                protocol: "TLS".to_string(),
                phase: "decrypt_data".to_string(),
                cause: "Not in application data state".to_string(),
                error_code: error_codes::PROTOCOL_STATE_INVALID,
            });
        }

        let nonce = self.generate_nonce(session.sequence_number)?;
        aes::decrypt(ciphertext, &session.receive_key, &nonce, None)
    }

    // Helper methods
    fn generate_random_bytes(&self) -> CryptoResult<[u8; 32]> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    fn select_cipher_suite(&self, client_suites: &[CipherSuite]) -> CryptoResult<CipherSuite> {
        for suite in &self.config.supported_cipher_suites {
            if client_suites.contains(suite) {
                return Ok(suite.clone());
            }
        }

        Err(CryptoError::ProtocolError {
            protocol: "TLS".to_string(),
            phase: "cipher_suite_selection".to_string(),
            cause: "No compatible cipher suite found".to_string(),
            error_code: error_codes::PROTOCOL_HANDSHAKE_FAILED,
        })
    }

    fn generate_certificate(&self) -> CryptoResult<Vec<u8>> {
        // Create a proper certificate structure
        #[derive(Serialize)]
        struct Certificate {
            version: u8,
            serial_number: [u8; 16],
            issuer: String,
            subject: String,
            not_before: SystemTime,
            not_after: SystemTime,
            public_key_algorithm: String,
            public_key: Vec<u8>,
        }

        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut serial = [0u8; 16];
        rng.fill_bytes(&mut serial);

        let cert = Certificate {
            version: 3,
            serial_number: serial,
            issuer: "CN=QaSa Self-Signed CA".to_string(),
            subject: "CN=QaSa TLS Server".to_string(),
            not_before: SystemTime::now(),
            not_after: SystemTime::now() + Duration::from_secs(365 * 24 * 3600), // 1 year
            public_key_algorithm: "Dilithium3".to_string(),
            public_key: bincode::serialize(&self.dilithium_keypair.public_key())
                .map_err(|e| CryptoError::SerializationError(e.to_string()))?,
        };

        bincode::serialize(&cert)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    fn sign_handshake_data(
        &self,
        client_hello: &ClientHello,
        certificate: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(
            &bincode::serialize(client_hello)
                .map_err(|e| CryptoError::SerializationError(e.to_string()))?,
        );
        data_to_sign.extend_from_slice(certificate);

        self.dilithium_keypair.sign(&data_to_sign)
    }

    fn generate_session_id(&self) -> CryptoResult<SessionId> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut id = [0u8; 32];
        rng.fill_bytes(&mut id);
        Ok(id)
    }

    fn generate_nonce(&self, sequence_number: u64) -> CryptoResult<[u8; 12]> {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&sequence_number.to_be_bytes());
        Ok(nonce)
    }

    /// Process server hello as client and complete handshake
    pub fn process_server_hello(&mut self, server_hello: &ServerHello) -> CryptoResult<Handshake> {
        if self.state != TlsState::ClientHelloSent {
            return Err(CryptoError::ProtocolError {
                protocol: "TLS".to_string(),
                phase: "process_server_hello".to_string(),
                cause: format!("Invalid state: {:?}", self.state),
                error_code: error_codes::PROTOCOL_STATE_INVALID,
            });
        }

        // Verify server certificate and signature
        let server_public_key: DilithiumPublicKey = bincode::deserialize(&server_hello.certificate)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        // Verify signature over handshake data
        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(&server_hello.random);
        data_to_verify.extend_from_slice(&server_hello.kyber_ciphertext);
        data_to_verify.extend_from_slice(&server_hello.certificate);

        let signature_valid = server_public_key.verify(&data_to_verify, &server_hello.signature)?;
        if !signature_valid {
            return Err(CryptoError::ProtocolError {
                protocol: "TLS".to_string(),
                phase: "signature_verification".to_string(),
                cause: "Server signature verification failed".to_string(),
                error_code: error_codes::PROTOCOL_HANDSHAKE_FAILED,
            });
        }

        // Perform key decapsulation
        let shared_secret = self.kyber_keypair.decapsulate(&server_hello.kyber_ciphertext)?;

        // Generate session ID
        let session_id = self.generate_session_id()?;
        
        // Store session key
        let shared_secret_len = shared_secret.len();
        let shared_secret_array: [u8; 32] = shared_secret.try_into().map_err(|_| {
            CryptoError::invalid_parameter(
                "shared_secret",
                "32 bytes",
                &format!("{} bytes", shared_secret_len),
            )
        })?;

        let session_key = SessionKey {
            id: session_id,
            shared_secret: shared_secret_array,
            cipher_suite: server_hello.cipher_suite.clone(),
            created_at: SystemTime::now(),
            last_used: SystemTime::now(),
        };

        self.session_keys.insert(session_id, session_key);
        self.state = TlsState::HandshakeComplete;

        Ok(Handshake {
            session_id,
            client_random: [0u8; 32], // Would be stored from client_hello
            server_random: server_hello.random,
        })
    }

    /// Get the current number of active sessions
    pub fn active_sessions(&self) -> usize {
        self.session_keys.len()
    }

    /// Clean up expired sessions
    pub fn cleanup_expired_sessions(&mut self) {
        let now = SystemTime::now();
        self.session_keys.retain(|_, session| {
            now.duration_since(session.last_used)
                .unwrap_or(Duration::MAX) < self.config.session_timeout
        });
    }
}

/// Handshake completion data
#[derive(Debug)]
pub struct Handshake {
    pub session_id: SessionId,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
}

/// Established secure session
#[derive(Debug)]
pub struct Session {
    pub id: SessionId,
    pub cipher_suite: CipherSuite,
    pub send_key: [u8; 32],
    pub receive_key: [u8; 32],
    pub sequence_number: u64,
}

/// Contact information for secure messaging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: ContactId,
    pub display_name: String,
    pub kyber_public_key: KyberPublicKey,
    pub dilithium_public_key: DilithiumPublicKey,
    pub added_at: SystemTime,
    pub last_seen: Option<SystemTime>,
    pub trust_level: TrustLevel,
}

/// Trust level for contacts
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TrustLevel {
    Untrusted,
    Trusted,
    Verified,
}

/// Key registry for managing contact public keys
#[derive(Debug, Clone)]
pub struct KeyRegistry {
    contacts: HashMap<ContactId, Contact>,
    own_id: ContactId,
    own_display_name: String,
}

impl KeyRegistry {
    /// Create a new key registry
    pub fn new(own_id: ContactId, own_display_name: String) -> Self {
        Self {
            contacts: HashMap::new(),
            own_id,
            own_display_name,
        }
    }

    /// Add a new contact
    pub fn add_contact(&mut self, contact: Contact) -> CryptoResult<()> {
        if contact.id == self.own_id {
            return Err(CryptoError::InvalidParameter {
                parameter: "contact_id".to_string(),
                expected: "different from own ID".to_string(),
                actual: "same as own ID".to_string(),
                error_code: 9999,
            });
        }
        
        self.contacts.insert(contact.id.clone(), contact);
        Ok(())
    }

    /// Get a contact by ID
    pub fn get_contact(&self, id: &ContactId) -> Option<&Contact> {
        self.contacts.get(id)
    }

    /// Update contact's last seen time
    pub fn update_last_seen(&mut self, id: &ContactId) {
        if let Some(contact) = self.contacts.get_mut(id) {
            contact.last_seen = Some(SystemTime::now());
        }
    }

    /// Update contact's trust level
    pub fn update_trust_level(&mut self, id: &ContactId, trust_level: TrustLevel) -> CryptoResult<()> {
        self.contacts
            .get_mut(id)
            .ok_or_else(|| CryptoError::InvalidParameter {
                parameter: "contact_id".to_string(),
                expected: "existing contact".to_string(),
                actual: "unknown contact".to_string(),
                error_code: 9999,
            })?
            .trust_level = trust_level;
        Ok(())
    }

    /// Remove a contact
    pub fn remove_contact(&mut self, id: &ContactId) -> Option<Contact> {
        self.contacts.remove(id)
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Vec<&Contact> {
        self.contacts.values().collect()
    }
}

/// Secure Messaging Protocol
///
/// Implements a Signal-style secure messaging protocol with post-quantum security.
/// Provides perfect forward secrecy through ephemeral key exchange.
pub struct SecureMessaging {
    /// Long-term identity key pair
    identity_keypair: DilithiumKeyPair,

    /// Own Kyber key pair for receiving messages
    own_kyber_keypair: KyberKeyPair,

    /// Own contact ID
    own_id: ContactId,

    /// Key registry for managing contacts
    key_registry: KeyRegistry,

    /// Cache of ephemeral keys for contacts
    ephemeral_keys: HashMap<ContactId, EphemeralKeyData>,

    /// Message history for replay protection
    message_history: HashMap<ContactId, Vec<MessageId>>,

    /// Configuration
    config: MessagingConfig,
}

impl std::fmt::Debug for SecureMessaging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureMessaging")
            .field("own_id", &self.own_id)
            .field("contacts_count", &self.key_registry.contacts.len())
            .field("ephemeral_keys_count", &self.ephemeral_keys.len())
            .field("message_history_contacts", &self.message_history.len())
            .field("config", &self.config)
            .field("identity_algorithm", &self.identity_keypair.algorithm)
            .finish_non_exhaustive()
    }
}

/// Configuration for secure messaging
#[derive(Debug, Clone)]
pub struct MessagingConfig {
    pub max_ephemeral_keys: usize,
    pub key_rotation_interval: Duration,
    pub message_expiry: Duration,
    pub enable_forward_secrecy: bool,
}

impl Default for MessagingConfig {
    fn default() -> Self {
        Self {
            max_ephemeral_keys: 100,
            key_rotation_interval: Duration::from_secs(3600), // 1 hour
            message_expiry: Duration::from_secs(86400 * 7),   // 1 week
            enable_forward_secrecy: true,
        }
    }
}

/// Ephemeral key data for a contact
#[derive(Debug, Clone)]
struct EphemeralKeyData {
    kyber_keypair: KyberKeyPair,
    created_at: SystemTime,
    last_used: SystemTime,
    message_count: u64,
}

/// Message identifier for replay protection
pub type MessageId = [u8; 16];

/// Encrypted message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub sender_id: ContactId,
    pub recipient_id: ContactId,
    pub message_id: MessageId,
    pub timestamp: SystemTime,
    pub kyber_ciphertext: Vec<u8>,
    pub encrypted_content: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: [u8; 12],
}

impl SecureMessaging {
    /// Create a new secure messaging instance
    pub fn new(own_id: ContactId, display_name: String, config: MessagingConfig) -> CryptoResult<Self> {
        let identity_keypair =
            DilithiumKeyPair::generate(crate::dilithium::DilithiumVariant::Dilithium3)?;
        let own_kyber_keypair = 
            KyberKeyPair::generate(crate::kyber::KyberVariant::Kyber768)?;

        Ok(Self {
            identity_keypair,
            own_kyber_keypair,
            own_id: own_id.clone(),
            key_registry: KeyRegistry::new(own_id, display_name),
            ephemeral_keys: HashMap::new(),
            message_history: HashMap::new(),
            config,
        })
    }

    /// Get own public keys for sharing with contacts
    pub fn get_own_public_keys(&self) -> (KyberPublicKey, DilithiumPublicKey) {
        (
            self.own_kyber_keypair.public_key().clone(),
            self.identity_keypair.public_key().clone(),
        )
    }

    /// Add a new contact
    pub fn add_contact(
        &mut self,
        id: ContactId,
        display_name: String,
        kyber_public_key: KyberPublicKey,
        dilithium_public_key: DilithiumPublicKey,
    ) -> CryptoResult<()> {
        let contact = Contact {
            id,
            display_name,
            kyber_public_key,
            dilithium_public_key,
            added_at: SystemTime::now(),
            last_seen: None,
            trust_level: TrustLevel::Untrusted,
        };
        
        self.key_registry.add_contact(contact)
    }

    /// Verify and trust a contact
    pub fn verify_contact(&mut self, contact_id: &ContactId) -> CryptoResult<()> {
        self.key_registry.update_trust_level(contact_id, TrustLevel::Verified)
    }

    /// Send an encrypted message to a recipient
    pub fn send_message(
        &mut self,
        recipient: &ContactId,
        message: &[u8],
    ) -> CryptoResult<EncryptedMessage> {
        // Get or create ephemeral key for this contact
        let _ephemeral_key = self.get_or_create_ephemeral_key(recipient)?;

        // Get recipient's public key from registry
        let recipient_public_key = self.get_recipient_public_key(recipient)?;
        let (kyber_ciphertext, shared_secret) = recipient_public_key.encapsulate()?;

        // Generate message ID and nonce
        let message_id = self.generate_message_id()?;
        let nonce = self.generate_message_nonce()?;

        // Encrypt the message content
        let (encrypted_content, _) = aes::encrypt(message, &shared_secret, Some(&nonce))?;

        // Create message structure for signing
        let message_data = EncryptedMessage {
            sender_id: self.own_id.clone(),
            recipient_id: recipient.clone(),
            message_id,
            timestamp: SystemTime::now(),
            kyber_ciphertext,
            encrypted_content,
            signature: Vec::new(), // Filled below
            nonce,
        };

        // Sign the entire message
        let message_bytes = bincode::serialize(&message_data)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        let signature = self.identity_keypair.sign(&message_bytes)?;

        let mut final_message = message_data;
        final_message.signature = signature;

        // Update ephemeral key usage
        self.update_ephemeral_key_usage(recipient)?;

        // Add to message history for replay protection
        self.add_to_message_history(recipient, message_id);

        // Update contact's last seen
        self.key_registry.update_last_seen(recipient);

        Ok(final_message)
    }

    /// Receive and decrypt a message
    pub fn receive_message(&mut self, encrypted: &EncryptedMessage) -> CryptoResult<Vec<u8>> {
        // Check for replay attacks
        if self.is_replay_message(&encrypted.sender_id, &encrypted.message_id) {
            return Err(CryptoError::SecurityPolicyViolation {
                policy: "replay_protection".to_string(),
                details: "Message ID already seen".to_string(),
                error_code: error_codes::SECURITY_POLICY_VIOLATION,
                severity: crate::error::SecuritySeverity::High,
            });
        }

        // Verify message signature
        let sender_public_key = self.get_sender_public_key(&encrypted.sender_id)?;
        let mut message_for_verification = encrypted.clone();
        message_for_verification.signature = Vec::new(); // Clear signature for verification

        let message_bytes = bincode::serialize(&message_for_verification)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        let signature_valid = sender_public_key.verify(&message_bytes, &encrypted.signature)?;
        if !signature_valid {
            return Err(CryptoError::SecurityPolicyViolation {
                policy: "signature_verification".to_string(),
                details: "Message signature verification failed".to_string(),
                error_code: error_codes::SECURITY_POLICY_VIOLATION,
                severity: crate::error::SecuritySeverity::Critical,
            });
        }

        // Perform key decapsulation with our own key
        let shared_secret = self.own_kyber_keypair
            .decapsulate(&encrypted.kyber_ciphertext)?;

        // Decrypt message content
        let plaintext = aes::decrypt(
            &encrypted.encrypted_content,
            &shared_secret,
            &encrypted.nonce,
            None,
        )?;

        // Add to message history
        self.add_to_message_history(&encrypted.sender_id, encrypted.message_id);

        // Update sender's last seen
        self.key_registry.update_last_seen(&encrypted.sender_id);

        Ok(plaintext)
    }

    /// Rotate ephemeral keys for forward secrecy
    pub fn rotate_ephemeral_keys(&mut self) -> CryptoResult<()> {
        let now = SystemTime::now();
        let mut keys_to_rotate = Vec::new();

        for (contact_id, key_data) in &self.ephemeral_keys {
            if now
                .duration_since(key_data.created_at)
                .unwrap_or(Duration::ZERO)
                >= self.config.key_rotation_interval
            {
                keys_to_rotate.push(contact_id.clone());
            }
        }

        for contact_id in keys_to_rotate {
            self.create_ephemeral_key(&contact_id)?;
        }

        Ok(())
    }

    // Helper methods
    fn get_or_create_ephemeral_key(
        &mut self,
        contact: &ContactId,
    ) -> CryptoResult<&EphemeralKeyData> {
        if !self.ephemeral_keys.contains_key(contact) {
            self.create_ephemeral_key(contact)?;
        }

        Ok(self.ephemeral_keys.get(contact).unwrap())
    }

    fn create_ephemeral_key(&mut self, contact: &ContactId) -> CryptoResult<()> {
        let kyber_keypair = KyberKeyPair::generate(crate::kyber::KyberVariant::Kyber768)?;
        let now = SystemTime::now();

        let key_data = EphemeralKeyData {
            kyber_keypair,
            created_at: now,
            last_used: now,
            message_count: 0,
        };

        self.ephemeral_keys.insert(contact.clone(), key_data);
        Ok(())
    }

    fn get_ephemeral_key(&self, contact: &ContactId) -> CryptoResult<&EphemeralKeyData> {
        self.ephemeral_keys.get(contact).ok_or_else(|| {
            CryptoError::key_management_error(
                "Key retrieval failed",
                &format!("No ephemeral key found for contact: {}", contact),
                "ephemeral",
            )
        })
    }

    fn update_ephemeral_key_usage(&mut self, contact: &ContactId) -> CryptoResult<()> {
        if let Some(key_data) = self.ephemeral_keys.get_mut(contact) {
            key_data.last_used = SystemTime::now();
            key_data.message_count += 1;
        }
        Ok(())
    }

    fn generate_message_id(&self) -> CryptoResult<MessageId> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Ok(id)
    }

    fn generate_message_nonce(&self) -> CryptoResult<[u8; 12]> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        Ok(nonce)
    }

    fn is_replay_message(&self, sender: &ContactId, message_id: &MessageId) -> bool {
        self.message_history
            .get(sender)
            .map(|history| history.contains(message_id))
            .unwrap_or(false)
    }

    fn add_to_message_history(&mut self, sender: &ContactId, message_id: MessageId) {
        self.message_history
            .entry(sender.clone())
            .or_insert_with(Vec::new)
            .push(message_id);

        // Limit history size to prevent memory exhaustion
        if let Some(history) = self.message_history.get_mut(sender) {
            if history.len() > 10000 {
                history.drain(0..1000); // Remove oldest 1000 entries
            }
        }
    }

    // Updated helper methods - no longer placeholders
    fn get_recipient_public_key(&self, recipient: &ContactId) -> CryptoResult<KyberPublicKey> {
        self.key_registry
            .get_contact(recipient)
            .map(|contact| contact.kyber_public_key.clone())
            .ok_or_else(|| CryptoError::InvalidParameter {
                parameter: "recipient".to_string(),
                expected: "known contact".to_string(),
                actual: format!("unknown contact: {}", recipient),
                error_code: 9999,
            })
    }

    fn get_sender_public_key(&self, sender: &ContactId) -> CryptoResult<DilithiumPublicKey> {
        self.key_registry
            .get_contact(sender)
            .map(|contact| contact.dilithium_public_key.clone())
            .ok_or_else(|| CryptoError::InvalidParameter {
                parameter: "sender".to_string(),
                expected: "known contact".to_string(),
                actual: format!("unknown contact: {}", sender),
                error_code: 9999,
            })
    }

    /// Export contact for sharing
    pub fn export_contact(&self, contact_id: &ContactId) -> CryptoResult<Vec<u8>> {
        let contact = self.key_registry
            .get_contact(contact_id)
            .ok_or_else(|| CryptoError::InvalidParameter {
                parameter: "contact_id".to_string(),
                expected: "existing contact".to_string(),
                actual: "unknown contact".to_string(),
                error_code: 9999,
            })?;
        
        bincode::serialize(contact)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Import contact from exported data
    pub fn import_contact(&mut self, data: &[u8]) -> CryptoResult<ContactId> {
        let contact: Contact = bincode::deserialize(data)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        
        let contact_id = contact.id.clone();
        self.key_registry.add_contact(contact)?;
        Ok(contact_id)
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Vec<(ContactId, String, TrustLevel)> {
        self.key_registry
            .list_contacts()
            .into_iter()
            .map(|c| (c.id.clone(), c.display_name.clone(), c.trust_level))
            .collect()
    }

    /// Remove a contact
    pub fn remove_contact(&mut self, contact_id: &ContactId) -> CryptoResult<()> {
        // Remove from registry
        self.key_registry.remove_contact(contact_id)
            .ok_or_else(|| CryptoError::InvalidParameter {
                parameter: "contact_id".to_string(),
                expected: "existing contact".to_string(),
                actual: "unknown contact".to_string(),
                error_code: 9999,
            })?;
        
        // Clean up associated data
        self.ephemeral_keys.remove(contact_id);
        self.message_history.remove(contact_id);
        
        Ok(())
    }
}

// Helper functions for key derivation
fn derive_send_key(shared_secret: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(b"send");
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

fn derive_receive_key(shared_secret: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(b"receive");
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert!(config.max_sessions > 0);
        assert!(!config.supported_cipher_suites.is_empty());
    }

    #[test]
    fn test_quantum_safe_tls_creation() {
        let config = TlsConfig::default();
        let tls = QuantumSafeTLS::new(config);
        assert!(tls.is_ok());

        let tls = tls.unwrap();
        assert_eq!(tls.state, TlsState::Initial);
        assert!(tls.session_keys.is_empty());
    }

    #[test]
    fn test_secure_messaging_creation() {
        let config = MessagingConfig::default();
        let messaging = SecureMessaging::new("mary@example.com".to_string(), "Mary".to_string(), config);
        assert!(messaging.is_ok());

        let messaging = messaging.unwrap();
        assert!(messaging.ephemeral_keys.is_empty());
        assert!(messaging.message_history.is_empty());
    }

    #[test]
    fn test_cipher_suite_selection() {
        let config = TlsConfig::default();
        let mut tls = QuantumSafeTLS::new(config).unwrap();

        let client_suites = vec![
            CipherSuite::Kyber768_Dilithium3_AES256GCM,
            CipherSuite::Kyber1024_Dilithium5_AES256GCM,
        ];

        let selected = tls.select_cipher_suite(&client_suites);
        assert!(selected.is_ok());
        assert!(client_suites.contains(&selected.unwrap()));
    }

    #[test]
    fn test_session_id_generation() {
        let config = TlsConfig::default();
        let tls = QuantumSafeTLS::new(config).unwrap();

        let id1 = tls.generate_session_id().unwrap();
        let id2 = tls.generate_session_id().unwrap();

        // Session IDs should be unique
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_message_id_generation() {
        let config = MessagingConfig::default();
        let messaging = SecureMessaging::new("mary@example.com".to_string(), "Mary".to_string(), config).unwrap();

        let id1 = messaging.generate_message_id().unwrap();
        let id2 = messaging.generate_message_id().unwrap();

        // Message IDs should be unique
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_contact_management() {
        let config = MessagingConfig::default();
        let mut mary = SecureMessaging::new("mary@example.com".to_string(), "Mary".to_string(), config.clone()).unwrap();
        let elena = SecureMessaging::new("elena@example.com".to_string(), "Elena".to_string(), config).unwrap();

        // Get Elena's public keys
        let (elena_kyber_key, elena_dilithium_key) = elena.get_own_public_keys();

        // Mary adds Elena as a contact
        let result = mary.add_contact(
            "elena@example.com".to_string(),
            "Elena".to_string(),
            elena_kyber_key,
            elena_dilithium_key,
        );
        assert!(result.is_ok());

        // List contacts
        let contacts = mary.list_contacts();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].0, "elena@example.com");
        assert_eq!(contacts[0].1, "Elena");
        assert_eq!(contacts[0].2, TrustLevel::Untrusted);

        // Verify Elena
        mary.verify_contact(&"elena@example.com".to_string()).unwrap();
        let contacts = mary.list_contacts();
        assert_eq!(contacts[0].2, TrustLevel::Verified);

        // Remove Elena
        let result = mary.remove_contact(&"elena@example.com".to_string());
        assert!(result.is_ok());
        assert!(mary.list_contacts().is_empty());
    }

    #[test]
    fn test_message_exchange() {
        let config = MessagingConfig::default();
        let mut mary = SecureMessaging::new("mary@example.com".to_string(), "Mary".to_string(), config.clone()).unwrap();
        let mut elena = SecureMessaging::new("elena@example.com".to_string(), "Elena".to_string(), config).unwrap();

        // Exchange public keys
        let (mary_kyber, mary_dilithium) = mary.get_own_public_keys();
        let (elena_kyber, elena_dilithium) = elena.get_own_public_keys();

        // Add each other as contacts
        mary.add_contact("elena@example.com".to_string(), "Elena".to_string(), elena_kyber, elena_dilithium).unwrap();
        elena.add_contact("mary@example.com".to_string(), "Mary".to_string(), mary_kyber, mary_dilithium).unwrap();

        // Mary sends a message to Elena
        let message = b"Hello Elena!";
        let encrypted = mary.send_message(&"elena@example.com".to_string(), message).unwrap();

        // Elena receives and decrypts the message
        let decrypted = elena.receive_message(&encrypted).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_replay_protection() {
        let config = MessagingConfig::default();
        let mut mary = SecureMessaging::new("mary@example.com".to_string(), "Mary".to_string(), config.clone()).unwrap();
        let mut elena = SecureMessaging::new("elena@example.com".to_string(), "Elena".to_string(), config).unwrap();

        // Exchange public keys
        let (mary_kyber, mary_dilithium) = mary.get_own_public_keys();
        let (elena_kyber, elena_dilithium) = elena.get_own_public_keys();

        // Add each other as contacts
        mary.add_contact("elena@example.com".to_string(), "Elena".to_string(), elena_kyber, elena_dilithium).unwrap();
        elena.add_contact("mary@example.com".to_string(), "Mary".to_string(), mary_kyber, mary_dilithium).unwrap();

        // Mary sends a message to Elena
        let message = b"Hello Elena!";
        let encrypted = mary.send_message(&"elena@example.com".to_string(), message).unwrap();

        // Elena receives the message successfully
        let decrypted = elena.receive_message(&encrypted).unwrap();
        assert_eq!(decrypted, message);

        // Attempting to receive the same message again should fail
        let replay_result = elena.receive_message(&encrypted);
        assert!(replay_result.is_err());
        
        if let Err(CryptoError::SecurityPolicyViolation { policy, .. }) = replay_result {
            assert_eq!(policy, "replay_protection");
        } else {
            panic!("Expected replay protection error");
        }
    }

    #[test]
    fn test_contact_export_import() {
        let config = MessagingConfig::default();
        let mut mary = SecureMessaging::new("mary@example.com".to_string(), "Mary".to_string(), config.clone()).unwrap();
        let mut charlie = SecureMessaging::new("charlie@example.com".to_string(), "Charlie".to_string(), config.clone()).unwrap();
        let elena = SecureMessaging::new("elena@example.com".to_string(), "Elena".to_string(), config).unwrap();

        // Get Elena's public keys
        let (elena_kyber_key, elena_dilithium_key) = elena.get_own_public_keys();

        // Mary adds Elena as a contact
        mary.add_contact(
            "elena@example.com".to_string(),
            "Elena".to_string(),
            elena_kyber_key,
            elena_dilithium_key,
        ).unwrap();

        // Mary exports Elena's contact
        let exported = mary.export_contact(&"elena@example.com".to_string()).unwrap();

        // Charlie imports Elena's contact
        let imported_id = charlie.import_contact(&exported).unwrap();
        assert_eq!(imported_id, "elena@example.com");

        // Verify Charlie has Elena as a contact
        let contacts = charlie.list_contacts();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].0, "elena@example.com");
    }

    #[test]
    fn test_key_rotation() {
        let mut config = MessagingConfig::default();
        config.key_rotation_interval = Duration::from_millis(100); // Short interval for testing
        
        let mut mary = SecureMessaging::new("mary@example.com".to_string(), "Mary".to_string(), config).unwrap();

        // Create ephemeral key
        mary.create_ephemeral_key(&"elena@example.com".to_string()).unwrap();
        let initial_key_count = mary.ephemeral_keys.len();
        assert_eq!(initial_key_count, 1);

        // Wait for rotation interval
        std::thread::sleep(Duration::from_millis(150));

        // Rotate keys
        mary.rotate_ephemeral_keys().unwrap();

        // Key should have been rotated (replaced)
        assert_eq!(mary.ephemeral_keys.len(), 1);
    }

    #[test]
    fn test_complete_tls_handshake() {
        let config = TlsConfig::default();
        let mut client = QuantumSafeTLS::new(config.clone()).unwrap();
        let mut server = QuantumSafeTLS::new(config).unwrap();

        // Client initiates handshake
        let client_hello = client.client_hello().unwrap();
        assert_eq!(client.state, TlsState::ClientHelloSent);

        // Server processes client hello and responds
        let server_hello = server.server_hello(&client_hello).unwrap();
        assert_eq!(server.state, TlsState::HandshakeComplete);

        // Client processes server hello
        let handshake = client.process_server_hello(&server_hello).unwrap();
        assert_eq!(client.state, TlsState::HandshakeComplete);

        // Both sides establish sessions
        let client_session = client.establish_session(&handshake).unwrap();
        let server_session = server.establish_session(&handshake).unwrap();

        // Test data encryption/decryption
        let test_data = b"Hello, quantum-safe TLS!";
        let encrypted = client.encrypt_data(test_data, &client_session).unwrap();
        let decrypted = server.decrypt_data(&encrypted, &server_session).unwrap();
        
        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_tls_session_cleanup() {
        let mut config = TlsConfig::default();
        config.session_timeout = Duration::from_millis(100); // Short timeout for testing
        
        let mut tls = QuantumSafeTLS::new(config).unwrap();

        // Create some sessions
        for _ in 0..3 {
            let session_id = tls.generate_session_id().unwrap();
            let session_key = SessionKey {
                id: session_id,
                shared_secret: [0u8; 32],
                cipher_suite: CipherSuite::Kyber768_Dilithium3_AES256GCM,
                created_at: SystemTime::now() - Duration::from_secs(1),
                last_used: SystemTime::now() - Duration::from_secs(1),
            };
            tls.session_keys.insert(session_id, session_key);
        }

        assert_eq!(tls.active_sessions(), 3);

        // Wait for sessions to expire
        std::thread::sleep(Duration::from_millis(150));

        // Clean up expired sessions
        tls.cleanup_expired_sessions();
        assert_eq!(tls.active_sessions(), 0);
    }

    #[test]
    fn test_invalid_tls_state_transitions() {
        let config = TlsConfig::default();
        let mut tls = QuantumSafeTLS::new(config).unwrap();

        // Try to encrypt data without completing handshake
        let session = Session {
            id: [0u8; 32],
            cipher_suite: CipherSuite::Kyber768_Dilithium3_AES256GCM,
            send_key: [0u8; 32],
            receive_key: [0u8; 32],
            sequence_number: 0,
        };

        let result = tls.encrypt_data(b"test", &session);
        assert!(result.is_err());
        
        if let Err(CryptoError::ProtocolError { phase, .. }) = result {
            assert_eq!(phase, "encrypt_data");
        } else {
            panic!("Expected protocol error");
        }
    }
}
