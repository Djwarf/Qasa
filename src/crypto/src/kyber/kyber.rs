use oqs::kem::{Algorithm, Kem};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::error::error_codes;
use crate::utils;

/// CRYSTALS-Kyber key pair for key encapsulation mechanisms (KEM)
/// 
/// This implementation uses the CRYSTALS-Kyber algorithm, a lattice-based
/// key encapsulation mechanism that is believed to be secure against 
/// quantum computer attacks.
///
/// # Security Properties
///
/// 1. Quantum-resistant security based on the module learning with errors (MLWE) problem
/// 2. Public keys and ciphertexts have small sizes compared to other post-quantum schemes
/// 3. Secret keys are automatically zeroed when the struct is dropped
/// 4. Provides IND-CCA2 security (indistinguishability under adaptive chosen-ciphertext attack)
///
/// # Examples
///
/// ```
/// use qasa::kyber::{KyberKeyPair, KyberVariant};
///
/// // Generate a new Kyber-768 key pair
/// let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
///
/// // Encapsulate a shared secret using the public key
/// let (ciphertext, shared_secret) = key_pair.encapsulate().unwrap();
///
/// // Decapsulate the shared secret using the private key
/// let decapsulated_secret = key_pair.decapsulate(&ciphertext).unwrap();
///
/// // The encapsulated and decapsulated secrets should match
/// assert_eq!(shared_secret, decapsulated_secret);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberKeyPair {
    /// Public key for encapsulation
    pub public_key: Vec<u8>,
    /// Secret key for decapsulation
    pub secret_key: Vec<u8>,
    /// The algorithm variant (Kyber512, Kyber768, or Kyber1024)
    pub algorithm: KyberVariant,
}

impl Drop for KyberKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

// Implement Zeroize manually instead of using the derive
impl Zeroize for KyberKeyPair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
        // We don't need to zeroize the public key or algorithm
    }
}

/// Public key only version of KyberKeyPair for sharing with others
///
/// This structure contains only the public key and algorithm variant,
/// making it safe to share with other parties for establishing secure
/// communication channels.
///
/// # Security Properties
///
/// 1. Contains no sensitive secret key material
/// 2. Can be freely shared without compromising security
/// 3. Used by recipients for encapsulating shared secrets
///
/// # Examples
///
/// ```
/// use qasa::kyber::{KyberKeyPair, KyberVariant};
///
/// // Generate a full key pair
/// let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
///
/// // Extract just the public key for sharing
/// let public_key = key_pair.public_key();
///
/// // A different party can use the public key to encapsulate a shared secret
/// let (ciphertext, shared_secret) = public_key.encapsulate().unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberPublicKey {
    /// Public key for encapsulation
    pub public_key: Vec<u8>,
    /// The algorithm variant (Kyber512, Kyber768, or Kyber1024)
    pub algorithm: KyberVariant,
}

/// CRYSTALS-Kyber algorithm variants with different security levels
///
/// Kyber offers three different parameter sets that trade off between
/// security and performance/key size. Each variant corresponds to a 
/// different NIST security level.
///
/// # Security Levels
///
/// * Kyber512: NIST Level 1 (equivalent to AES-128)
/// * Kyber768: NIST Level 3 (equivalent to AES-192)
/// * Kyber1024: NIST Level 5 (equivalent to AES-256)
///
/// For most applications, Kyber768 provides a good balance between
/// security and performance.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KyberVariant {
    /// Kyber512 (NIST security level 1)
    Kyber512,
    /// Kyber768 (NIST security level 3, recommended)
    Kyber768,
    /// Kyber1024 (NIST security level 5)
    Kyber1024,
}

impl fmt::Display for KyberVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KyberVariant::Kyber512 => write!(f, "Kyber512"),
            KyberVariant::Kyber768 => write!(f, "Kyber768"),
            KyberVariant::Kyber1024 => write!(f, "Kyber1024"),
        }
    }
}

impl KyberVariant {
    /// Get the OQS algorithm for this variant
    ///
    /// This is an internal helper method that converts our KyberVariant
    /// enum to the corresponding OQS library Algorithm enum.
    ///
    /// # Returns
    ///
    /// The OQS Algorithm enum corresponding to this variant
    fn oqs_algorithm(&self) -> Algorithm {
        match self {
            KyberVariant::Kyber512 => Algorithm::Kyber512,
            KyberVariant::Kyber768 => Algorithm::Kyber768,
            KyberVariant::Kyber1024 => Algorithm::Kyber1024,
        }
    }
    
    /// Get the security level of this Kyber variant
    ///
    /// The security level is defined according to NIST standards:
    /// - Level 1: At least as hard to break as AES-128
    /// - Level 3: At least as hard to break as AES-192
    /// - Level 5: At least as hard to break as AES-256
    ///
    /// # Returns
    ///
    /// A number representing the NIST security level (1, 3, or 5)
    pub fn security_level(&self) -> u8 {
        match self {
            KyberVariant::Kyber512 => 1,
            KyberVariant::Kyber768 => 3,
            KyberVariant::Kyber1024 => 5,
        }
    }
    
    /// Get the public key size for this variant in bytes
    ///
    /// # Returns
    ///
    /// The size of the public key in bytes for this variant
    pub fn public_key_size(&self) -> usize {
        match self {
            KyberVariant::Kyber512 => 800,
            KyberVariant::Kyber768 => 1184,
            KyberVariant::Kyber1024 => 1568,
        }
    }
    
    /// Get the secret key size for this variant in bytes
    ///
    /// # Returns
    ///
    /// The size of the secret key in bytes for this variant
    pub fn secret_key_size(&self) -> usize {
        match self {
            KyberVariant::Kyber512 => 1632,
            KyberVariant::Kyber768 => 2400,
            KyberVariant::Kyber1024 => 3168,
        }
    }
    
    /// Get the ciphertext size for this variant in bytes
    ///
    /// This is the size of the encapsulated key that would be sent
    /// to the recipient during key exchange.
    ///
    /// # Returns
    ///
    /// The size of the ciphertext in bytes for this variant
    pub fn ciphertext_size(&self) -> usize {
        match self {
            KyberVariant::Kyber512 => 768,
            KyberVariant::Kyber768 => 1088,
            KyberVariant::Kyber1024 => 1568,
        }
    }
    
    /// Get the shared secret size in bytes (same for all variants)
    ///
    /// All Kyber variants produce a 32-byte (256-bit) shared secret,
    /// which is suitable for use as a symmetric encryption key.
    ///
    /// # Returns
    ///
    /// The size of the shared secret in bytes (32)
    pub fn shared_secret_size(&self) -> usize {
        32 // All Kyber variants use 32-byte shared secrets
    }
}

impl KyberKeyPair {
    /// Generate a new Kyber key pair with the specified variant
    ///
    /// This function generates a new random key pair for the specified
    /// Kyber variant. The key pair includes both public and private keys
    /// and can be used for key encapsulation.
    ///
    /// # Arguments
    ///
    /// * `variant` - The Kyber variant to use (Kyber512, Kyber768, or Kyber1024)
    ///
    /// # Returns
    ///
    /// A new KyberKeyPair or an error if key generation failed
    ///
    /// # Security Considerations
    ///
    /// 1. Uses cryptographically secure random number generation
    /// 2. Secret key material is protected in memory and zeroed on drop
    /// 3. Higher security variants (Kyber768, Kyber1024) provide stronger security guarantees
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::kyber::{KyberKeyPair, KyberVariant};
    ///
    /// // Generate a Kyber-768 key pair (NIST Level 3 security)
    /// let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    /// ```
    pub fn generate(variant: KyberVariant) -> Result<Self, CryptoError> {
        let alg = variant.oqs_algorithm();
        let kyber = Kem::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        let (public_key, secret_key) = kyber.keypair()
            .map_err(|e| CryptoError::kyber_error("Key generation failed", &e.to_string(), error_codes::KYBER_KEY_GENERATION_FAILED))?;
            
        Ok(Self {
            public_key: public_key.into_vec(),
            secret_key: secret_key.into_vec(),
            algorithm: variant,
        })
    }
    
    /// Encapsulate a shared secret using this key pair's public key
    ///
    /// This generates a shared secret and encapsulates it with the public key.
    /// Both the ciphertext and shared secret are returned. The ciphertext can be
    /// sent to the owner of the key pair, who can then decapsulate it to recover
    /// the same shared secret.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * `ciphertext` - The encapsulated shared secret (to be sent to the recipient)
    /// * `shared_secret` - The shared secret (to be used for symmetric encryption)
    ///
    /// Or an error if encapsulation fails
    ///
    /// # Security Considerations
    ///
    /// 1. The shared secret is generated using a cryptographically secure random number generator
    /// 2. This operation only requires the public key, so it can be performed by anyone
    /// 3. The same shared secret is only revealed to the holder of the corresponding private key
    /// 4. The shared secret can be used as a key for symmetric encryption (e.g., AES-GCM)
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::kyber::{KyberKeyPair, KyberVariant};
    ///
    /// // Generate a key pair
    /// let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    ///
    /// // Encapsulate a shared secret
    /// let (ciphertext, shared_secret) = key_pair.encapsulate().unwrap();
    ///
    /// // The ciphertext can be sent to the recipient
    /// // The shared secret can be used for symmetric encryption
    /// ```
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let kyber = Kem::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        // Create a public key from bytes using the Kem instance
        let pk = kyber.public_key_from_bytes(&self.public_key)
            .ok_or_else(|| CryptoError::kyber_error("Encapsulation failed", "Failed to create public key from bytes", error_codes::KYBER_KEY_GENERATION_FAILED))?;
        
        let (ciphertext, shared_secret) = kyber.encapsulate(&pk)
            .map_err(|e| CryptoError::kyber_error("Encapsulation failed", &e.to_string(), error_codes::KYBER_ENCAPSULATION_FAILED))?;
            
        Ok((ciphertext.into_vec(), shared_secret.into_vec()))
    }
    
    /// Decapsulate a shared secret using this key pair's secret key
    ///
    /// This takes a ciphertext produced by encapsulate() and extracts the 
    /// shared secret using the secret key. The resulting shared secret will
    /// be identical to the one produced during encapsulation.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext containing the encapsulated shared secret
    ///
    /// # Returns
    ///
    /// The shared secret or an error if decapsulation fails
    ///
    /// # Security Considerations
    ///
    /// 1. This operation requires the secret key, so only the intended recipient can recover the shared secret
    /// 2. If decapsulation fails, it may indicate tampering or corruption of the ciphertext
    /// 3. Kyber provides IND-CCA2 security, so invalid ciphertexts will be detected and rejected
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::kyber::{KyberKeyPair, KyberVariant};
    ///
    /// // Generate a key pair
    /// let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    ///
    /// // Encapsulate a shared secret
    /// let (ciphertext, original_secret) = key_pair.encapsulate().unwrap();
    ///
    /// // Decapsulate the shared secret
    /// let recovered_secret = key_pair.decapsulate(&ciphertext).unwrap();
    ///
    /// // The recovered secret should match the original secret
    /// assert_eq!(original_secret, recovered_secret);
    /// ```
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let kyber = Kem::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        // Create a secret key from bytes using the Kem instance
        let sk = kyber.secret_key_from_bytes(&self.secret_key)
            .ok_or_else(|| CryptoError::kyber_error("Decapsulation failed", "Failed to create secret key from bytes", error_codes::KYBER_KEY_GENERATION_FAILED))?;
        
        // Create a ciphertext from bytes using the Kem instance
        let ct = kyber.ciphertext_from_bytes(ciphertext)
            .ok_or_else(|| CryptoError::kyber_error("Decapsulation failed", "Failed to create ciphertext from bytes", error_codes::KYBER_KEY_GENERATION_FAILED))?;
        
        let shared_secret = kyber.decapsulate(&sk, &ct)
            .map_err(|e| CryptoError::kyber_error("Decapsulation failed", &e.to_string(), error_codes::KYBER_DECAPSULATION_FAILED))?;
        
        Ok(shared_secret.into_vec())
    }
    
    /// Extract the public key from this key pair
    ///
    /// This is useful when you need to share your public key with others
    /// while keeping the secret key private.
    ///
    /// # Returns
    ///
    /// A KyberPublicKey containing only the public key information
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::kyber::{KyberKeyPair, KyberVariant};
    ///
    /// // Generate a key pair
    /// let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    ///
    /// // Extract the public key to share with others
    /// let public_key = key_pair.public_key();
    /// ```
    pub fn public_key(&self) -> KyberPublicKey {
        KyberPublicKey {
            public_key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }
    
    /// Verify that the public and secret keys match
    ///
    /// This is done by encapsulating a random shared secret and then decapsulating it.
    /// If the keys match, the decapsulated shared secret will match the encapsulated one.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the keys match, or an error if verification fails
    ///
    /// # Security Considerations
    ///
    /// 1. This function performs a full encapsulation and decapsulation to verify key correctness
    /// 2. It's useful to check key integrity after loading keys from storage
    /// 3. Failure could indicate key corruption or tampering
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::kyber::{KyberKeyPair, KyberVariant};
    ///
    /// // Generate a key pair
    /// let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
    ///
    /// // Verify that the public and secret keys match
    /// key_pair.verify_key_pair().unwrap();
    /// ```
    pub fn verify_key_pair(&self) -> Result<(), CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let kyber = Kem::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        // Create a public key from bytes using the Kem instance
        let pk = kyber.public_key_from_bytes(&self.public_key)
            .ok_or_else(|| CryptoError::kyber_error("Key verification failed", "Failed to create public key from bytes", error_codes::KYBER_KEY_GENERATION_FAILED))?;
        
        // Create a secret key from bytes using the Kem instance
        let sk = kyber.secret_key_from_bytes(&self.secret_key)
            .ok_or_else(|| CryptoError::kyber_error("Key verification failed", "Failed to create secret key from bytes", error_codes::KYBER_KEY_GENERATION_FAILED))?;
        
        // Perform a test encapsulation
        let (ct, ss1) = kyber.encapsulate(&pk)
            .map_err(|e| CryptoError::kyber_error("Encapsulation failed", &e.to_string(), error_codes::KYBER_ENCAPSULATION_FAILED))?;
        
        // Perform a test decapsulation
        let ss2 = kyber.decapsulate(&sk, &ct)
            .map_err(|e| CryptoError::kyber_error("Decapsulation failed", &e.to_string(), error_codes::KYBER_DECAPSULATION_FAILED))?;
        
        // Check if the shared secrets match
        if ss1 == ss2 {
            Ok(())
        } else {
            Err(CryptoError::kyber_error("Key verification failed", "Shared secrets do not match", error_codes::KYBER_KEY_GENERATION_FAILED))
        }
    }
    
    /// Serialize the key pair to bytes
    ///
    /// # Returns
    ///
    /// The serialized key pair or an error
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        bincode::serialize(self)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }
    
    /// Deserialize a key pair from bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized key pair
    ///
    /// # Returns
    ///
    /// The deserialized key pair or an error
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        bincode::deserialize(data)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }
}

impl KyberPublicKey {
    /// Encapsulate a shared secret using this public key
    ///
    /// This is used by someone who wants to establish a shared secret
    /// with the owner of the corresponding private key.
    ///
    /// # Returns
    ///
    /// A tuple containing (ciphertext, shared_secret) or an error
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let kyber = Kem::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;
        
        // Create a public key from the stored bytes using the Kem instance
        let pk = kyber.public_key_from_bytes(&self.public_key)
            .ok_or_else(|| CryptoError::kyber_error("Encapsulation failed", "Failed to create public key from bytes", error_codes::KYBER_KEY_GENERATION_FAILED))?;
        
        let (ciphertext, shared_secret) = kyber.encapsulate(&pk)
            .map_err(|e| CryptoError::kyber_error("Encapsulation failed", &e.to_string(), error_codes::KYBER_ENCAPSULATION_FAILED))?;
            
        Ok((ciphertext.into_vec(), shared_secret.into_vec()))
    }
    
    /// Serialize the public key to bytes
    ///
    /// # Returns
    ///
    /// The serialized public key or an error
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        bincode::serialize(self)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }
    
    /// Deserialize a public key from bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized public key
    ///
    /// # Returns
    ///
    /// The deserialized public key or an error
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        bincode::deserialize(data)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }
    
    /// Generate a fingerprint of this public key
    ///
    /// This can be used as a short identifier for the public key.
    ///
    /// # Returns
    ///
    /// A hex string representation of the fingerprint
    pub fn fingerprint(&self) -> String {
        let mut data = Vec::with_capacity(self.public_key.len() + 1);
        data.push(self.algorithm.security_level());
        data.extend_from_slice(&self.public_key);
        
        // Generate SHA-256 hash and take first 8 bytes as fingerprint
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        
        utils::to_hex(&hash[0..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kyber_key_generation() {
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.secret_key.is_empty());
        
        // Verify key sizes
        assert_eq!(key_pair.public_key.len(), KyberVariant::Kyber768.public_key_size());
        assert_eq!(key_pair.secret_key.len(), KyberVariant::Kyber768.secret_key_size());
    }
    
    #[test]
    fn test_encapsulation_decapsulation() {
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let (ciphertext, shared_secret1) = key_pair.encapsulate().unwrap();
        let shared_secret2 = key_pair.decapsulate(&ciphertext).unwrap();
        
        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), KyberVariant::Kyber768.shared_secret_size());
        assert_eq!(ciphertext.len(), KyberVariant::Kyber768.ciphertext_size());
    }
    
    #[test]
    fn test_public_key_encapsulation() {
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let pub_key = key_pair.public_key();
        
        // Encapsulate with public key
        let (ciphertext, shared_secret1) = pub_key.encapsulate().unwrap();
        
        // Decapsulate with private key
        let shared_secret2 = key_pair.decapsulate(&ciphertext).unwrap();
        
        assert_eq!(shared_secret1, shared_secret2);
    }
    
    #[test]
    fn test_key_verification() {
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        assert!(key_pair.verify_key_pair().is_ok());
    }
    
    #[test]
    fn test_serialization() {
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let serialized = key_pair.to_bytes().unwrap();
        let deserialized = KyberKeyPair::from_bytes(&serialized).unwrap();
        
        assert_eq!(key_pair.algorithm, deserialized.algorithm);
        assert_eq!(key_pair.public_key, deserialized.public_key);
        assert_eq!(key_pair.secret_key, deserialized.secret_key);
    }
    
    #[test]
    fn test_public_key_serialization() {
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let pub_key = key_pair.public_key();
        
        let serialized = pub_key.to_bytes().unwrap();
        let deserialized = KyberPublicKey::from_bytes(&serialized).unwrap();
        
        assert_eq!(pub_key.algorithm, deserialized.algorithm);
        assert_eq!(pub_key.public_key, deserialized.public_key);
    }
    
    #[test]
    fn test_public_key_fingerprint() {
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let pub_key = key_pair.public_key();
        
        let fingerprint = pub_key.fingerprint();
        assert_eq!(fingerprint.len(), 16); // 8 bytes as hex = 16 chars
    }
    
    #[test]
    fn test_invalid_ciphertext() {
        let key_pair = KyberKeyPair::generate(KyberVariant::Kyber768).unwrap();
        let result = key_pair.decapsulate(&[0u8; 10]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_all_variants() {
        // Test all Kyber variants
        for variant in [KyberVariant::Kyber512, KyberVariant::Kyber768, KyberVariant::Kyber1024].iter() {
            let key_pair = KyberKeyPair::generate(*variant).unwrap();
            let (ciphertext, shared_secret1) = key_pair.encapsulate().unwrap();
            let shared_secret2 = key_pair.decapsulate(&ciphertext).unwrap();
            
            assert_eq!(shared_secret1, shared_secret2);
            assert_eq!(shared_secret1.len(), variant.shared_secret_size());
            assert_eq!(ciphertext.len(), variant.ciphertext_size());
        }
    }
} 