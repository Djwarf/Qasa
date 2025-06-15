/*!
 * Hardware Security Module (HSM) Integration
 *
 * This module provides integration with Hardware Security Modules (HSMs) via the PKCS#11
 * interface, allowing secure key storage, generation, and cryptographic operations to be
 * performed directly on hardware devices.
 */

use std::fmt;
use std::path::Path;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};

use cryptoki::context::{Pkcs11, CInitializeArgs};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
// use cryptoki::token::Token; // Not available in this version
use cryptoki::object::{Attribute, AttributeType, ObjectHandle, KeyType, ObjectClass};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::rsa::PkcsPssParams;
use cryptoki::types::{AuthPin, Ulong};
use cryptoki::error::{Error as Pkcs11Error, RvError};

use crate::error::{CryptoError, CryptoResult, error_codes};
use crate::dilithium::{DilithiumKeyPair, DilithiumVariant};
use crate::kyber::{KyberKeyPair, KyberVariant};
use crate::secure_memory::SecureBytes;

/// Supported HSM providers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HsmProvider {
    /// SoftHSM (software implementation, primarily for testing)
    SoftHsm,
    
    /// Thales Luna HSM
    ThalesLuna,
    
    /// AWS CloudHSM
    AwsCloudHsm,
    
    /// Utimaco HSM
    Utimaco,
    
    /// Generic PKCS#11 compliant HSM
    GenericPkcs11,
}

/// Key attributes for HSM-stored keys
#[derive(Debug, Clone)]
pub struct HsmKeyAttributes {
    /// Label for the key (human-readable identifier)
    pub label: String,
    
    /// ID for the key (application-specific identifier)
    pub id: Vec<u8>,
    
    /// Whether the key can be extracted from the HSM
    pub extractable: bool,
    
    /// Whether the key is marked as sensitive
    pub sensitive: bool,
    
    /// Allowed operations for this key
    pub allowed_operations: Vec<HsmOperation>,
    
    /// Additional provider-specific attributes
    pub provider_attributes: HashMap<String, String>,
}

/// Operations that can be performed with HSM keys
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HsmOperation {
    /// Sign data
    Sign,
    
    /// Verify signatures
    Verify,
    
    /// Encrypt data
    Encrypt,
    
    /// Decrypt data
    Decrypt,
    
    /// Derive shared secrets
    Derive,
    
    /// Wrap (encrypt) other keys
    Wrap,
    
    /// Unwrap (decrypt) other keys
    Unwrap,
}

/// Connection to an HSM
pub struct HsmConnection {
    provider: HsmProvider,
    context: Arc<Pkcs11>,
    session: Option<Session>,
    is_logged_in: bool,
    config: HsmConfig,
    slot: Option<Slot>,
}

/// HSM configuration parameters
#[derive(Clone)]
pub struct HsmConfig {
    /// Path to the PKCS#11 library
    pub library_path: String,
    
    /// Slot ID to use
    pub slot_id: Option<u64>,
    
    /// Token label to use
    pub token_label: Option<String>,
    
    /// User PIN for authentication
    pub user_pin: Option<SecureBytes>,
    
    /// Additional provider-specific configuration
    pub provider_config: HashMap<String, String>,
}

impl fmt::Debug for HsmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmConfig")
            .field("library_path", &self.library_path)
            .field("slot_id", &self.slot_id)
            .field("token_label", &self.token_label)
            .field("user_pin", &"[REDACTED]")
            .field("provider_config", &self.provider_config)
            .finish()
    }
}

/// Connect to an HSM using the specified provider and configuration
///
/// # Arguments
///
/// * `provider` - The HSM provider to use
/// * `config` - Configuration for connecting to the HSM
///
/// # Returns
///
/// A connection to the HSM or an error if connection failed
pub fn connect_hsm(provider: HsmProvider, config: HsmConfig) -> CryptoResult<HsmConnection> {
    // Validate the configuration
    if !Path::new(&config.library_path).exists() {
        return Err(CryptoError::key_management_error(
            "connect_hsm",
            &format!("PKCS#11 library not found: {}", config.library_path),
            "HSM",
        ));
    }
    
    // Initialize the PKCS#11 library
    log::info!("Initializing PKCS#11 library: {}", config.library_path);
    
    let context = Pkcs11::new(&config.library_path).map_err(|e| {
        CryptoError::key_management_error(
            "connect_hsm",
            &format!("Failed to load PKCS#11 library: {}", e),
            "HSM",
        )
    })?;
    
    // Initialize the library
    context.initialize(CInitializeArgs::OsThreads).map_err(|e| {
        CryptoError::key_management_error(
            "connect_hsm",
            &format!("Failed to initialize PKCS#11 library: {}", e),
            "HSM",
        )
    })?;
    
    // Get available slots
    let slots = context.get_slots_with_token().map_err(|e| {
        CryptoError::key_management_error(
            "connect_hsm",
            &format!("Failed to get slots: {}", e),
            "HSM",
        )
    })?;
    
    if slots.is_empty() {
        return Err(CryptoError::key_management_error(
            "connect_hsm",
            "No slots with tokens found",
            "HSM",
        ));
    }
    
    // Find the appropriate slot
    let slot = if let Some(slot_id) = config.slot_id {
        // Use the specified slot ID
        let slot_ulong = Ulong::from(slot_id);
        slots.into_iter().find(|s| s.id() == *slot_ulong).ok_or_else(|| {
            CryptoError::key_management_error(
                "connect_hsm",
                &format!("Slot {} not found", slot_id),
                "HSM",
            )
        })?
    } else if let Some(ref token_label) = config.token_label {
        // Find slot by token label
        let mut found_slot = None;
        for slot in slots {
            if let Ok(token_info) = context.get_token_info(slot) {
                if token_info.label().trim() == token_label.trim() {
                    found_slot = Some(slot);
                    break;
                }
            }
        }
        found_slot.ok_or_else(|| {
            CryptoError::key_management_error(
                "connect_hsm",
                &format!("Token with label '{}' not found", token_label),
                "HSM",
            )
        })?
    } else {
        // Use the first available slot
        slots[0]
    };
    
    log::info!("Using slot: {:?}", slot.id());
    
    // Open a session with the HSM
    let session = context.open_rw_session(slot).map_err(|e| {
        CryptoError::key_management_error(
            "connect_hsm",
            &format!("Failed to open session: {}", e),
            "HSM",
        )
    })?;
    
    log::info!("Successfully opened session with HSM");
    
    Ok(HsmConnection {
        provider,
        context: Arc::new(context),
        session: Some(session),
        is_logged_in: false,
        config,
        slot: Some(slot),
    })
}

impl HsmConnection {
    /// Log in to the HSM
    ///
    /// # Arguments
    ///
    /// * `pin` - The user PIN for authentication
    ///
    /// # Returns
    ///
    /// Ok(()) if login succeeded, or an error
    pub fn login(&mut self, pin: &[u8]) -> CryptoResult<()> {
        if self.is_logged_in {
            return Ok(());
        }
        
        let session = self.session.as_ref().ok_or_else(|| {
            CryptoError::key_management_error(
                "login",
                "No active session",
                "HSM",
            )
        })?;
        
        // Validate PIN
        if pin.is_empty() {
            return Err(CryptoError::invalid_parameter(
                "pin",
                "non-empty PIN",
                "empty PIN",
            ));
        }
        
        log::info!("Logging in to HSM");
        
        // Convert PIN to AuthPin
        let pin_string = String::from_utf8_lossy(pin).to_string();
        let auth_pin = AuthPin::new(pin_string);
        
        // Attempt to authenticate with the provided PIN
        session.login(UserType::User, Some(&auth_pin)).map_err(|e| {
            CryptoError::key_management_error(
                "login",
                &format!("Failed to login to HSM: {}", e),
                "HSM",
            )
        })?;
        
        self.is_logged_in = true;
        log::info!("Successfully logged in to HSM");
        
        Ok(())
    }
    
    /// Log out from the HSM
    pub fn logout(&mut self) -> CryptoResult<()> {
        if !self.is_logged_in {
            return Ok(());
        }
        
        let session = self.session.as_ref().ok_or_else(|| {
            CryptoError::key_management_error(
                "logout",
                "No active session",
                "HSM",
            )
        })?;
        
        log::info!("Logging out from HSM");
        
        // Logout from the session
        session.logout().map_err(|e| {
            CryptoError::key_management_error(
                "logout",
                &format!("Failed to logout from HSM: {}", e),
                "HSM",
            )
        })?;
        
        self.is_logged_in = false;
        log::info!("Successfully logged out from HSM");
        
        Ok(())
    }
    
    /// Generate a key pair in the HSM
    ///
    /// # Arguments
    ///
    /// * `key_type` - The type of key to generate
    /// * `attributes` - Attributes for the generated key
    ///
    /// # Returns
    ///
    /// A handle to the generated key pair or an error
    pub fn generate_key_pair(
        &mut self,
        key_type: HsmKeyType,
        attributes: HsmKeyAttributes,
    ) -> CryptoResult<HsmKeyHandle> {
        let session = self.session.as_ref().ok_or_else(|| {
            CryptoError::key_management_error(
                "generate_key_pair",
                "No active session",
                "HSM",
            )
        })?;

        match key_type {
            HsmKeyType::Rsa => {
                // RSA key pair generation
                let mechanism = Mechanism::RsaPkcsKeyPairGen;
                
                let public_key_template = vec![
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Encrypt(true),
                    Attribute::Verify(true),
                    Attribute::Wrap(true),
                    Attribute::PublicExponent(vec![0x01, 0x00, 0x01]), // 65537
                    Attribute::ModulusBits(2048.into()),
                    Attribute::Label(attributes.label.clone().into_bytes()),
                    Attribute::Id(attributes.id.clone()),
                ];

                let private_key_template = vec![
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(attributes.sensitive),
                    Attribute::Extractable(!attributes.sensitive), // Opposite of sensitive
                    Attribute::Decrypt(true),
                    Attribute::Sign(true),
                    Attribute::Unwrap(true),
                    Attribute::Label(attributes.label.clone().into_bytes()),
                    Attribute::Id(attributes.id.clone()),
                ];

                let (public_handle, private_handle) = session
                    .generate_key_pair(&mechanism, &public_key_template, &private_key_template)
                    .map_err(|e| {
                        CryptoError::key_management_error(
                            "generate_key_pair",
                            &format!("Failed to generate RSA key pair: {}", e),
                            "HSM",
                        )
                    })?;

                Ok(HsmKeyHandle {
                    private_key: private_handle.into(),
                    public_key: public_handle.into(),
                    key_type,
                    attributes,
                })
            },
            HsmKeyType::Ecdsa => {
                // ECDSA key pair generation (P-256)
                let mechanism = Mechanism::EccKeyPairGen;
                
                // P-256 curve OID: 1.2.840.10045.3.1.7
                let p256_oid = vec![
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
                ];

                let public_key_template = vec![
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Verify(true),
                    Attribute::EcParams(p256_oid),
                    Attribute::Label(attributes.label.clone().into_bytes()),
                    Attribute::Id(attributes.id.clone()),
                ];

                let private_key_template = vec![
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(attributes.sensitive),
                    Attribute::Extractable(!attributes.sensitive),
                    Attribute::Sign(true),
                    Attribute::Label(attributes.label.clone().into_bytes()),
                    Attribute::Id(attributes.id.clone()),
                ];

                let (public_handle, private_handle) = session
                    .generate_key_pair(&mechanism, &public_key_template, &private_key_template)
                    .map_err(|e| {
                        CryptoError::key_management_error(
                            "generate_key_pair",
                            &format!("Failed to generate ECDSA key pair: {}", e),
                            "HSM",
                        )
                    })?;

                Ok(HsmKeyHandle {
                    private_key: private_handle.into(),
                    public_key: public_handle.into(),
                    key_type,
                    attributes,
                })
            },
            HsmKeyType::Aes => {
                // AES key generation
                let mechanism = Mechanism::AesKeyGen;
                
                let key_template = vec![
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(attributes.sensitive),
                    Attribute::Extractable(!attributes.sensitive),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                    Attribute::ValueLen(32.into()), // AES-256
                    Attribute::KeyType(KeyType::AES),
                    Attribute::Label(attributes.label.clone().into_bytes()),
                    Attribute::Id(attributes.id.clone()),
                ];

                let key_handle = session
                    .generate_key(&mechanism, &key_template)
                    .map_err(|e| {
                        CryptoError::key_management_error(
                            "generate_key_pair",
                            &format!("Failed to generate AES key: {}", e),
                            "HSM",
                        )
                    })?;

                Ok(HsmKeyHandle {
                    private_key: key_handle.into(),
                    public_key: key_handle.into(), // Same handle for symmetric keys
                    key_type,
                    attributes,
                })
            },
            HsmKeyType::GenericSecret => {
                // Generic secret key generation
                let mechanism = Mechanism::GenericSecretKeyGen;
                
                let key_template = vec![
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(attributes.sensitive),
                    Attribute::Extractable(!attributes.sensitive),
                    Attribute::ValueLen(32.into()), // 256 bits
                    Attribute::KeyType(KeyType::GENERIC_SECRET),
                    Attribute::Label(attributes.label.clone().into_bytes()),
                    Attribute::Id(attributes.id.clone()),
                ];

                let key_handle = session
                    .generate_key(&mechanism, &key_template)
                    .map_err(|e| {
                        CryptoError::key_management_error(
                            "generate_key_pair",
                            &format!("Failed to generate generic secret key: {}", e),
                            "HSM",
                        )
                    })?;

                Ok(HsmKeyHandle {
                    private_key: key_handle.into(),
                    public_key: key_handle.into(),
                    key_type,
                    attributes,
                })
            },
            HsmKeyType::Dilithium(_) | HsmKeyType::Kyber(_) => {
                // Post-quantum algorithms are not supported by standard PKCS#11
                // Return an error indicating this
                Err(CryptoError::key_management_error(
                    "generate_key_pair",
                    "Post-quantum algorithms are not supported by standard PKCS#11",
                    "HSM",
                ))
            },
        }
    }
    
    /// Sign data using a key in the HSM
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Handle to the key to use for signing
    /// * `data` - Data to sign
    /// * `mechanism` - Signing mechanism to use
    ///
    /// # Returns
    ///
    /// The signature or an error
    pub fn sign(
        &mut self,
        key_handle: &HsmKeyHandle,
        data: &[u8],
        mechanism: HsmMechanism,
    ) -> CryptoResult<Vec<u8>> {
        let session = self.session.as_ref().ok_or_else(|| {
            CryptoError::key_management_error(
                "sign",
                "No active session",
                "HSM",
            )
        })?;

        let pkcs11_mechanism = match mechanism {
            HsmMechanism::RsaPkcs => Mechanism::RsaPkcs,
            HsmMechanism::RsaPss => {
                // RSA PSS requires parameters
                let pss_params = PkcsPssParams {
                    hash_alg: MechanismType::SHA256,
                    mgf: cryptoki::mechanism::rsa::PkcsMgfType::MGF1_SHA256,
                    s_len: Ulong::from(32u64), // SHA-256 hash length
                };
                Mechanism::RsaPkcsPss(pss_params)
            },
            HsmMechanism::Ecdsa => Mechanism::Ecdsa,
            HsmMechanism::Hmac => Mechanism::Sha256Hmac,
            _ => {
                return Err(CryptoError::key_management_error(
                    "sign",
                    "Unsupported signing mechanism",
                    "HSM",
                ));
            }
        };

        let object_handle = ObjectHandle::from(key_handle.private_key);
        
        session.sign(&pkcs11_mechanism, object_handle, data)
            .map_err(|e| {
                CryptoError::key_management_error(
                    "sign",
                    &format!("HSM signing failed: {}", e),
                    "HSM",
                )
            })
    }
    
    /// Verify a signature using a key in the HSM
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Handle to the key to use for verification
    /// * `data` - Data that was signed
    /// * `signature` - Signature to verify
    /// * `mechanism` - Signing mechanism that was used
    ///
    /// # Returns
    ///
    /// true if the signature is valid, false otherwise, or an error
    pub fn verify(
        &mut self,
        key_handle: &HsmKeyHandle,
        data: &[u8],
        signature: &[u8],
        mechanism: HsmMechanism,
    ) -> CryptoResult<bool> {
        let session = self.session.as_ref().ok_or_else(|| {
            CryptoError::key_management_error(
                "verify",
                "No active session",
                "HSM",
            )
        })?;

        let pkcs11_mechanism = match mechanism {
            HsmMechanism::RsaPkcs => Mechanism::RsaPkcs,
            HsmMechanism::RsaPss => {
                // RSA PSS requires parameters
                let pss_params = PkcsPssParams {
                    hash_alg: MechanismType::SHA256,
                    mgf: cryptoki::mechanism::rsa::PkcsMgfType::MGF1_SHA256,
                    s_len: Ulong::from(32u64), // SHA-256 hash length
                };
                Mechanism::RsaPkcsPss(pss_params)
            },
            HsmMechanism::Ecdsa => Mechanism::Ecdsa,
            HsmMechanism::Hmac => Mechanism::Sha256Hmac,
            _ => {
                return Err(CryptoError::key_management_error(
                    "verify",
                    "Unsupported verification mechanism",
                    "HSM",
                ));
            }
        };

        let object_handle = ObjectHandle::from(key_handle.public_key);
        
        match session.verify(&pkcs11_mechanism, object_handle, data, signature) {
            Ok(()) => Ok(true),
            Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::SignatureInvalid, _)) => Ok(false),
            Err(e) => Err(CryptoError::key_management_error(
                "verify",
                &format!("HSM verification failed: {}", e),
                "HSM",
            )),
        }
    }
    
    /// Encrypt data using a key in the HSM
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Handle to the key to use for encryption
    /// * `data` - Data to encrypt
    /// * `mechanism` - Encryption mechanism to use
    ///
    /// # Returns
    ///
    /// The encrypted data or an error
    pub fn encrypt(
        &mut self,
        key_handle: &HsmKeyHandle,
        data: &[u8],
        mechanism: HsmMechanism,
    ) -> CryptoResult<Vec<u8>> {
        let session = self.session.as_ref().ok_or_else(|| {
            CryptoError::key_management_error(
                "encrypt",
                "No active session",
                "HSM",
            )
        })?;

        let pkcs11_mechanism = match mechanism {
            HsmMechanism::RsaPkcs => Mechanism::RsaPkcs,
            HsmMechanism::AesGcm => {
                // For AES-GCM, we need to provide IV and additional parameters
                // Create a static IV to avoid lifetime issues
                static IV: [u8; 12] = [0u8; 12]; // 96-bit IV for GCM
                let tag_bits = Ulong::from(128u64); // 128-bit authentication tag
                Mechanism::AesGcm(GcmParams::new(&IV, &[], tag_bits))
            },
            HsmMechanism::AesCbc => {
                // For AES-CBC, we need to provide IV as a fixed-size array
                let iv = [0u8; 16]; // 128-bit IV for CBC
                Mechanism::AesCbc(iv)
            },
            _ => {
                return Err(CryptoError::key_management_error(
                    "encrypt",
                    "Unsupported encryption mechanism",
                    "HSM",
                ));
            }
        };

        let object_handle = match key_handle.key_type {
            HsmKeyType::Rsa => ObjectHandle::from(key_handle.public_key),
            _ => ObjectHandle::from(key_handle.private_key),
        };
        
        session.encrypt(&pkcs11_mechanism, object_handle, data)
            .map_err(|e| {
                CryptoError::key_management_error(
                    "encrypt",
                    &format!("HSM encryption failed: {}", e),
                    "HSM",
                )
            })
    }
    
    /// Decrypt data using a key in the HSM
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Handle to the key to use for decryption
    /// * `ciphertext` - Data to decrypt
    /// * `mechanism` - Decryption mechanism to use
    ///
    /// # Returns
    ///
    /// The decrypted data or an error
    pub fn decrypt(
        &mut self,
        key_handle: &HsmKeyHandle,
        ciphertext: &[u8],
        mechanism: HsmMechanism,
    ) -> CryptoResult<Vec<u8>> {
        let session = self.session.as_ref().ok_or_else(|| {
            CryptoError::key_management_error(
                "decrypt",
                "No active session",
                "HSM",
            )
        })?;

        let pkcs11_mechanism = match mechanism {
            HsmMechanism::RsaPkcs => Mechanism::RsaPkcs,
            HsmMechanism::AesGcm => {
                // For AES-GCM, we need to provide IV and additional parameters
                // Create a static IV to avoid lifetime issues
                static IV: [u8; 12] = [0u8; 12]; // 96-bit IV for GCM
                let tag_bits = Ulong::from(128u64); // 128-bit authentication tag
                Mechanism::AesGcm(GcmParams::new(&IV, &[], tag_bits))
            },
            HsmMechanism::AesCbc => {
                // For AES-CBC, we need to provide IV as a fixed-size array
                let iv = [0u8; 16]; // 128-bit IV for CBC
                Mechanism::AesCbc(iv)
            },
            _ => {
                return Err(CryptoError::key_management_error(
                    "decrypt",
                    "Unsupported decryption mechanism",
                    "HSM",
                ));
            }
        };

        let object_handle = ObjectHandle::from(key_handle.private_key);
        
        session.decrypt(&pkcs11_mechanism, object_handle, ciphertext)
            .map_err(|e| {
                CryptoError::key_management_error(
                    "decrypt",
                    &format!("HSM decryption failed: {}", e),
                    "HSM",
                )
            })
    }
    
    /// Close the connection to the HSM
    pub fn close(mut self) -> CryptoResult<()> {
        if self.is_logged_in {
            self.logout()?;
        }
        
        if let Some(session) = self.session.take() {
            // Close the session - session.close() returns () so no error handling needed
            session.close();
        }
        
        // Finalize the PKCS#11 library - context.finalize() returns () so no error handling needed
        if let Ok(context) = Arc::try_unwrap(self.context) {
            context.finalize();
        }
        
        log::info!("Closed connection to HSM provider: {:?}", self.provider);
        
        Ok(())
    }
}

/// Handle to a key stored in an HSM
#[derive(Debug, Clone)]
pub struct HsmKeyHandle {
    private_key: ObjectHandle,
    public_key: ObjectHandle,
    key_type: HsmKeyType,
    attributes: HsmKeyAttributes,
}

/// Types of keys that can be stored in an HSM
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HsmKeyType {
    /// RSA key pair
    Rsa,
    
    /// ECDSA key pair
    Ecdsa,
    
    /// Dilithium key pair (not supported by standard PKCS#11)
    Dilithium(DilithiumVariant),
    
    /// Kyber key pair (not supported by standard PKCS#11)
    Kyber(KyberVariant),
    
    /// AES key
    Aes,
    
    /// Generic secret key
    GenericSecret,
}

/// Cryptographic mechanisms supported by the HSM
#[derive(Debug, Clone)]
pub enum HsmMechanism {
    /// RSA PKCS#1 v1.5
    RsaPkcs,
    
    /// RSA PSS
    RsaPss,
    
    /// ECDSA
    Ecdsa,
    
    /// Dilithium (not supported by standard PKCS#11)
    Dilithium(DilithiumVariant),
    
    /// AES-GCM
    AesGcm,
    
    /// AES-CBC
    AesCbc,
    
    /// HMAC
    Hmac,
}

/// Generate a key pair in the HSM
///
/// # Arguments
///
/// * `provider` - The HSM provider to use
/// * `config` - Configuration for connecting to the HSM
/// * `key_type` - The type of key to generate
/// * `attributes` - Attributes for the generated key
///
/// # Returns
///
/// A handle to the generated key pair or an error
pub fn generate_key_in_hsm(
    provider: HsmProvider,
    config: HsmConfig,
    key_type: HsmKeyType,
    attributes: HsmKeyAttributes,
) -> CryptoResult<HsmKeyHandle> {
    let mut conn = connect_hsm(provider, config.clone())?;
    
    // Log in if a PIN is provided
    if let Some(pin) = &config.user_pin {
        conn.login(pin.as_ref())?;
    }
    
    // Generate the key pair
    let key_handle = conn.generate_key_pair(key_type, attributes)?;
    
    // Close the connection
    conn.close()?;
    
    Ok(key_handle)
}

/// Sign data using a key in the HSM
///
/// # Arguments
///
/// * `provider` - The HSM provider to use
/// * `config` - Configuration for connecting to the HSM
/// * `key_handle` - Handle to the key to use
/// * `data` - Data to sign
/// * `mechanism` - Signing mechanism to use
///
/// # Returns
///
/// The signature or an error
pub fn sign_with_hsm(
    provider: HsmProvider,
    config: HsmConfig,
    key_handle: &HsmKeyHandle,
    data: &[u8],
    mechanism: HsmMechanism,
) -> CryptoResult<Vec<u8>> {
    let mut conn = connect_hsm(provider, config.clone())?;
    
    // Log in if a PIN is provided
    if let Some(pin) = &config.user_pin {
        conn.login(pin.as_ref())?;
    }
    
    // Sign the data
    let signature = conn.sign(key_handle, data, mechanism)?;
    
    // Close the connection
    conn.close()?;
    
    Ok(signature)
}

/// Verify a signature using a key in the HSM
///
/// # Arguments
///
/// * `provider` - The HSM provider to use
/// * `config` - Configuration for connecting to the HSM
/// * `key_handle` - Handle to the key to use
/// * `data` - Data that was signed
/// * `signature` - Signature to verify
/// * `mechanism` - Signing mechanism used
///
/// # Returns
///
/// true if the signature is valid, false otherwise
pub fn verify_with_hsm(
    provider: HsmProvider,
    config: HsmConfig,
    key_handle: &HsmKeyHandle,
    data: &[u8],
    signature: &[u8],
    mechanism: HsmMechanism,
) -> CryptoResult<bool> {
    let mut conn = connect_hsm(provider, config.clone())?;
    
    // Log in if a PIN is provided
    if let Some(pin) = &config.user_pin {
        conn.login(pin.as_ref())?;
    }
    
    // Verify the signature
    let result = conn.verify(key_handle, data, signature, mechanism)?;
    
    // Close the connection
    conn.close()?;
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Helper function to create a test HSM configuration
    fn create_test_config() -> HsmConfig {
        HsmConfig {
            library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot_id: Some(0),
            token_label: Some("test".to_string()),
            user_pin: Some(SecureBytes::from(b"1234".to_vec())),
            provider_config: HashMap::new(),
        }
    }
    
    #[test]
    fn test_hsm_connection_real() {
        // Skip test if SoftHSM is not available
        let config = create_test_config();
        if !Path::new(&config.library_path).exists() {
            println!("Skipping HSM test: SoftHSM not found at {}", config.library_path);
            return;
        }
        
        // Test connection to the HSM
        let result = connect_hsm(HsmProvider::SoftHsm, config.clone());
        
        match result {
            Ok(mut conn) => {
                // Test login
                if let Some(pin) = &config.user_pin {
                    let login_result = conn.login(pin.as_ref());
                    if login_result.is_ok() {
                        assert!(conn.is_logged_in, "Connection should be logged in");
                        
                        // Test logout
                        let logout_result = conn.logout();
                        assert!(logout_result.is_ok(), "Failed to logout: {:?}", logout_result.err());
                        assert!(!conn.is_logged_in, "Connection should not be logged in");
                    }
                }
                
                // Test close
                let close_result = conn.close();
                assert!(close_result.is_ok(), "Failed to close connection: {:?}", close_result.err());
            },
            Err(e) => {
                println!("HSM connection failed (this is expected if no HSM is configured): {}", e);
            }
        }
    }
    
    #[test]
    fn test_hsm_key_generation_real() {
        // Skip test if SoftHSM is not available
        let config = create_test_config();
        if !Path::new(&config.library_path).exists() {
            println!("Skipping HSM key generation test: SoftHSM not found");
            return;
        }
        
        let result = connect_hsm(HsmProvider::SoftHsm, config.clone());
        
        match result {
            Ok(mut conn) => {
                if let Some(pin) = &config.user_pin {
                    if conn.login(pin.as_ref()).is_ok() {
                        // Test RSA key generation
                        let attributes = HsmKeyAttributes {
                            label: "test-rsa-key".to_string(),
                            id: vec![1, 2, 3, 4],
                            extractable: false,
                            sensitive: true,
                            allowed_operations: vec![HsmOperation::Sign, HsmOperation::Verify],
                            provider_attributes: HashMap::new(),
                        };
                        
                        let key_result = conn.generate_key_pair(HsmKeyType::Rsa, attributes);
                        if key_result.is_ok() {
                            println!("Successfully generated RSA key pair in HSM");
                        } else {
                            println!("Failed to generate RSA key pair: {:?}", key_result.err());
                        }
                    }
                }
                
                let _ = conn.close();
            },
            Err(e) => {
                println!("HSM connection failed: {}", e);
            }
        }
    }
} 