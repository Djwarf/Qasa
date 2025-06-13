/*! 
 * CRYSTALS-Dilithium implementation for quantum-resistant digital signatures
 *
 * This module implements the CRYSTALS-Dilithium algorithm for digital signatures
 * as standardized by NIST for post-quantum cryptography.
 */

use crate::error::{CryptoError, error_codes};
use crate::utils;
use crate::dilithium::{CompressionLevel, CompressedSignature, compress_signature, decompress_signature};
use zeroize::Zeroize;

use std::fmt;
use std::convert::TryFrom;
use std::time::Duration;

use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};

/// CRYSTALS-Dilithium key pair for digital signatures
///
/// This implementation uses the CRYSTALS-Dilithium algorithm, a lattice-based
/// digital signature scheme that is believed to be secure against
/// quantum computer attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DilithiumKeyPair {
    /// Public key for signature verification
    pub public_key: Vec<u8>,
    /// Secret key for signature generation
    pub secret_key: Vec<u8>,
    /// The algorithm variant (Dilithium2, Dilithium3, or Dilithium5)
    pub algorithm: DilithiumVariant,
}

impl Drop for DilithiumKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

// Implement Zeroize manually instead of using the derive
impl Zeroize for DilithiumKeyPair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
        // We don't need to zeroize the public key or algorithm
    }
}

/// Public key only version of DilithiumKeyPair for sharing with others
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DilithiumPublicKey {
    /// Public key for signature verification
    pub public_key: Vec<u8>,
    /// The algorithm variant (Dilithium2, Dilithium3, or Dilithium5)
    pub algorithm: DilithiumVariant,
}

/// CRYSTALS-Dilithium algorithm variants with different security levels
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DilithiumVariant {
    /// Dilithium2 (NIST security level 2)
    Dilithium2,
    /// Dilithium3 (NIST security level 3, recommended)
    Dilithium3,
    /// Dilithium5 (NIST security level 5)
    Dilithium5,
}

impl fmt::Display for DilithiumVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DilithiumVariant::Dilithium2 => write!(f, "Dilithium2"),
            DilithiumVariant::Dilithium3 => write!(f, "Dilithium3"),
            DilithiumVariant::Dilithium5 => write!(f, "Dilithium5"),
        }
    }
}

impl DilithiumVariant {
    /// Get the OQS algorithm name for this variant
    fn oqs_algorithm(&self) -> Algorithm {
        match self {
            DilithiumVariant::Dilithium2 => Algorithm::Dilithium2,
            DilithiumVariant::Dilithium3 => Algorithm::Dilithium3,
            DilithiumVariant::Dilithium5 => Algorithm::Dilithium5,
        }
    }

    /// Get the security level of this variant
    pub fn security_level(&self) -> u8 {
        match self {
            DilithiumVariant::Dilithium2 => 2,
            DilithiumVariant::Dilithium3 => 3,
            DilithiumVariant::Dilithium5 => 5,
        }
    }

    /// Get the public key size for this variant in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            DilithiumVariant::Dilithium2 => 1312,
            DilithiumVariant::Dilithium3 => 1952,
            DilithiumVariant::Dilithium5 => 2592,
        }
    }

    /// Get the secret key size for this variant in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            DilithiumVariant::Dilithium2 => 2528,
            DilithiumVariant::Dilithium3 => 4000,
            DilithiumVariant::Dilithium5 => 4864,
        }
    }

    /// Get the signature size for this variant in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            DilithiumVariant::Dilithium2 => 2420,
            DilithiumVariant::Dilithium3 => 3293,
            DilithiumVariant::Dilithium5 => 4595,
        }
    }

    /// Choose the most appropriate variant for a resource-constrained environment
    /// based on available memory and desired security level
    ///
    /// # Arguments
    ///
    /// * `min_security_level` - Minimum required security level (2, 3, or 5)
    /// * `available_memory_kb` - Available memory in kilobytes
    ///
    /// # Returns
    ///
    /// The most appropriate DilithiumVariant for the environment or None if
    /// no suitable variant exists for the given constraints
    pub fn for_constrained_environment(
        min_security_level: u8,
        available_memory_kb: usize,
    ) -> Option<Self> {
        // Calculate rough memory requirements for each variant (in KB)
        // These are approximate values based on key and signature sizes plus overhead
        const DILITHIUM2_MEM: usize = 8; // ~8KB for Dilithium2
        const DILITHIUM3_MEM: usize = 12; // ~12KB for Dilithium3
        const DILITHIUM5_MEM: usize = 16; // ~16KB for Dilithium5

        match (min_security_level, available_memory_kb) {
            // If security level requirement is 5, we must use Dilithium5
            (5, mem) if mem >= DILITHIUM5_MEM => Some(Self::Dilithium5),

            // If security level requirement is 3, we can use Dilithium3 or Dilithium5
            (3, mem) if mem >= DILITHIUM3_MEM => Some(Self::Dilithium3),

            // If security level requirement is 2, we can use any variant
            (2, mem) if mem >= DILITHIUM2_MEM => Some(Self::Dilithium2),
            (_, mem) if mem >= DILITHIUM5_MEM => Some(Self::Dilithium5),
            (_, mem) if mem >= DILITHIUM3_MEM => Some(Self::Dilithium3),
            (_, mem) if mem >= DILITHIUM2_MEM => Some(Self::Dilithium2),

            // No suitable variant for the given constraints
            _ => None,
        }
    }

    /// Get the approximate memory usage for this variant in kilobytes
    pub fn memory_requirement_kb(&self) -> usize {
        match self {
            DilithiumVariant::Dilithium2 => 8,  // ~8KB
            DilithiumVariant::Dilithium3 => 12, // ~12KB
            DilithiumVariant::Dilithium5 => 16, // ~16KB
        }
    }
}

/// A memory-efficient implementation of Dilithium for resource-constrained environments
pub struct LeanDilithium {
    /// The algorithm variant
    variant: DilithiumVariant,
    /// Optional cached instance of Sig for repeated operations
    sig_instance: Option<Sig>,
}

impl Drop for LeanDilithium {
    fn drop(&mut self) {
        self.release_resources();
    }
}

impl LeanDilithium {
    /// Create a new LeanDilithium instance without pre-initializing the Sig instance
    ///
    /// # Arguments
    ///
    /// * `variant` - The Dilithium variant to use
    ///
    /// # Returns
    ///
    /// A new LeanDilithium instance
    pub fn new(variant: DilithiumVariant) -> Self {
        Self {
            variant,
            sig_instance: None,
        }
    }

    /// Initialize or get the Sig instance (lazy initialization)
    fn get_sig(&mut self) -> Result<&mut Sig, CryptoError> {
        if self.sig_instance.is_none() {
            let alg = self.variant.oqs_algorithm();
            self.sig_instance =
                Some(Sig::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?);
        }

        // This unwrap is safe because we just ensured the Option is Some
        Ok(self.sig_instance.as_mut().unwrap())
    }

    /// Sign a message with the given secret key
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `secret_key` - The secret key to use for signing
    ///
    /// # Returns
    ///
    /// The signature or an error
    pub fn sign(&mut self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = self.get_sig()?;

        // Create a secret key from bytes using the Sig instance
        let sk = sig.secret_key_from_bytes(secret_key).ok_or_else(|| {
            CryptoError::dilithium_error(
                "Signature generation failed",
                "Failed to create secret key from bytes",
                error_codes::DILITHIUM_SIGNING_FAILED,
            )
        })?;

        let signature = sig.sign(message, &sk).map_err(|e| {
            CryptoError::dilithium_error(
                "Signature generation failed",
                &e.to_string(),
                error_codes::DILITHIUM_SIGNING_FAILED,
            )
        })?;

        Ok(signature.into_vec())
    }

    /// Verify a signature using the given public key
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    /// * `public_key` - The public key to use for verification
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify(
        &mut self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        let sig = self.get_sig()?;

        // Create public key and signature objects from bytes
        let pk = sig.public_key_from_bytes(public_key).ok_or_else(|| {
            CryptoError::dilithium_error(
                "Signature verification failed",
                "Failed to create public key from bytes",
                error_codes::DILITHIUM_SIGNING_FAILED,
            )
        })?;

        let sig_obj = sig.signature_from_bytes(signature).ok_or_else(|| {
            CryptoError::dilithium_error(
                "Signature verification failed",
                "Failed to create signature from bytes",
                error_codes::DILITHIUM_SIGNING_FAILED,
            )
        })?;

        match sig.verify(message, &sig_obj, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Release any resources held by this instance
    ///
    /// This frees the Sig instance, which can be important in memory-constrained
    /// environments. It's automatically called when the LeanDilithium instance is dropped.
    pub fn release_resources(&mut self) {
        // Drop the Sig instance to free memory
        self.sig_instance = None;
    }

    /// Verify multiple signatures in batch mode to save memory and reduce initialization overhead
    ///
    /// # Arguments
    ///
    /// * `batch` - A vector of (message, signature, public_key) tuples to verify
    ///
    /// # Returns
    ///
    /// A vector of verification results (true for valid, false for invalid) or an error
    pub fn verify_batch(
        &mut self,
        batch: &[(&[u8], &[u8], &[u8])],
    ) -> Result<Vec<bool>, CryptoError> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }

        let sig = self.get_sig()?;
        let mut results = Vec::with_capacity(batch.len());

        for (message, signature, public_key) in batch {
            // Create objects from bytes for each iteration
            let pk = match sig.public_key_from_bytes(public_key) {
                Some(pk) => pk,
                None => {
                    results.push(false);
                    continue;
                }
            };

            let sig_obj = match sig.signature_from_bytes(signature) {
                Some(s) => s,
                None => {
                    results.push(false);
                    continue;
                }
            };

            let is_valid = sig.verify(message, &sig_obj, &pk).is_ok();
            results.push(is_valid);
        }

        Ok(results)
    }
}

/// Streamlined signing function for resource-constrained environments
///
/// This function minimizes memory usage by creating and releasing resources
/// only for the duration of the signing operation.
///
/// # Arguments
///
/// * `message` - The message to sign
/// * `secret_key` - The secret key to use for signing
/// * `variant` - The Dilithium variant to use
///
/// # Returns
///
/// The signature or an error
pub fn lean_sign(
    message: &[u8],
    secret_key: &[u8],
    variant: DilithiumVariant,
) -> Result<Vec<u8>, CryptoError> {
    let mut lean = LeanDilithium::new(variant);
    let result = lean.sign(message, secret_key);
    lean.release_resources();
    result
}

/// Streamlined verification function for resource-constrained environments
///
/// This function minimizes memory usage by creating and releasing resources
/// only for the duration of the verification operation.
///
/// # Arguments
///
/// * `message` - The message that was signed
/// * `signature` - The signature to verify
/// * `public_key` - The public key to use for verification
/// * `variant` - The Dilithium variant to use
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise
pub fn lean_verify(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    variant: DilithiumVariant,
) -> Result<bool, CryptoError> {
    let mut lean = LeanDilithium::new(variant);
    let result = lean.verify(message, signature, public_key);
    lean.release_resources();
    result
}

/// Verify multiple signatures efficiently for resource-constrained environments
///
/// This function intelligently groups verification operations by variant to
/// minimize resource usage during batch verification.
///
/// # Arguments
///
/// * `batch` - A vector of (message, signature, public_key, variant) tuples
///
/// # Returns
///
/// A vector of verification results or an error
pub fn lean_verify_batch(
    batch: &[(&[u8], &[u8], &[u8], DilithiumVariant)],
) -> Result<Vec<bool>, CryptoError> {
    if batch.is_empty() {
        return Ok(Vec::new());
    }

    // Group by variant to minimize instance creation
    let mut results = vec![false; batch.len()];

    // Group items by variant
    let mut variant_groups = std::collections::HashMap::new();

    for (i, (message, signature, public_key, variant)) in batch.iter().enumerate() {
        variant_groups
            .entry(*variant)
            .or_insert_with(Vec::new)
            .push((i, *message, *signature, *public_key));
    }

    // Process each variant group
    for (variant, group) in variant_groups {
        let mut lean = LeanDilithium::new(variant);

        // Convert to the format expected by verify_batch
        let batch_items: Vec<(&[u8], &[u8], &[u8])> = group
            .iter()
            .map(|(_, msg, sig, pk)| (*msg, *sig, *pk))
            .collect();

        // Verify the batch
        let batch_results = lean.verify_batch(&batch_items)?;

        // Update the results array
        for ((i, _, _, _), result) in group.iter().zip(batch_results.iter()) {
            results[*i] = *result;
        }

        // Free resources
        lean.release_resources();
    }

    Ok(results)
}

impl DilithiumKeyPair {
    /// Generate a new Dilithium key pair with the specified variant
    ///
    /// # Arguments
    ///
    /// * `variant` - The Dilithium variant to use (Dilithium2, Dilithium3, or Dilithium5)
    ///
    /// # Returns
    ///
    /// A new DilithiumKeyPair or an error if key generation failed
    pub fn generate(variant: DilithiumVariant) -> Result<Self, CryptoError> {
        let alg = variant.oqs_algorithm();
        let dilithium = Sig::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;

        let (public_key, secret_key) = dilithium.keypair().map_err(|e| {
            CryptoError::dilithium_error(
                "Key generation failed",
                &e.to_string(),
                error_codes::DILITHIUM_KEY_GENERATION_FAILED,
            )
        })?;

        Ok(Self {
            public_key: public_key.into_vec(),
            secret_key: secret_key.into_vec(),
            algorithm: variant,
        })
    }

    /// Sign a message with this key pair's secret key
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// The signature or an error
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let dilithium = Sig::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;

        // Create a secret key from bytes using the Sig instance
        let sk = dilithium
            .secret_key_from_bytes(&self.secret_key)
            .ok_or_else(|| {
                CryptoError::dilithium_error(
                    "Signature generation failed",
                    "Failed to create secret key from bytes",
                    error_codes::DILITHIUM_SIGNING_FAILED,
                )
            })?;

        let signature = dilithium.sign(message, &sk).map_err(|e| {
            CryptoError::dilithium_error(
                "Signature generation failed",
                &e.to_string(),
                error_codes::DILITHIUM_SIGNING_FAILED,
            )
        })?;

        Ok(signature.into_vec())
    }

    /// Verify a signature with this key pair's public key
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// Ok(true) if the signature is valid, Ok(false) if invalid, Err(CryptoError) on error
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let dilithium = Sig::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;

        // Create a public key from bytes using the Sig instance
        let pk = dilithium
            .public_key_from_bytes(&self.public_key)
            .ok_or_else(|| {
                CryptoError::dilithium_error(
                    "Signature verification failed",
                    "Failed to create public key from bytes",
                    error_codes::DILITHIUM_SIGNING_FAILED,
                )
            })?;

        // Create a signature from bytes using the Sig instance
        let sig = dilithium.signature_from_bytes(signature).ok_or_else(|| {
            CryptoError::dilithium_error(
                "Signature verification failed",
                "Failed to create signature from bytes",
                error_codes::DILITHIUM_SIGNING_FAILED,
            )
        })?;

        match dilithium.verify(message, &sig, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Extract the public key from this key pair
    ///
    /// This is useful when you need to share your public key with others
    /// while keeping the secret key private.
    ///
    /// # Returns
    ///
    /// A DilithiumPublicKey containing only the public key information
    pub fn public_key(&self) -> DilithiumPublicKey {
        DilithiumPublicKey {
            public_key: self.public_key.clone(),
            algorithm: self.algorithm,
        }
    }

    /// Serialize the key pair to bytes
    ///
    /// # Returns
    ///
    /// The serialized key pair or an error
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        bincode::serialize(self).map_err(|e| CryptoError::SerializationError(e.to_string()))
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
        bincode::deserialize(data).map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Verify a signature with a public key
    ///
    /// This is a static method that can be used to verify a signature using
    /// a public key that is not part of a key pair.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The Dilithium algorithm variant to use
    /// * `public_key` - The public key to use for verification
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// Ok(true) if the signature is valid, Ok(false) if invalid, Err(CryptoError) on error
    pub fn verify_with_public_key(
        algorithm: DilithiumVariant,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let alg = algorithm.oqs_algorithm();
        let dilithium = Sig::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;

        // Create a public key from bytes using the Sig instance
        let pk = dilithium.public_key_from_bytes(public_key).ok_or_else(|| {
            CryptoError::dilithium_error(
                "Signature verification failed",
                "Failed to create public key from bytes",
                error_codes::DILITHIUM_SIGNING_FAILED,
            )
        })?;

        // Create a signature from bytes using the Sig instance
        let sig = dilithium.signature_from_bytes(signature).ok_or_else(|| {
            CryptoError::dilithium_error(
                "Signature verification failed",
                "Failed to create signature from bytes",
                error_codes::DILITHIUM_SIGNING_FAILED,
            )
        })?;

        match dilithium.verify(message, &sig, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Test key generation for constant-time execution
    #[cfg(feature = "constant-time-testing")]
    pub fn generate_test_constant_time(
        variant: DilithiumVariant,
        config: &crate::security::constant_time::ConstantTimeConfig,
    ) -> Result<crate::security::constant_time::ConstantTimeResult, CryptoError> {
        use crate::security::constant_time::verify_constant_time;
        
        let operation = |_: &()| {
            let _ = Self::generate(variant);
        };
        
        let input_generator = || ();
        
        verify_constant_time(operation, input_generator, config)
    }

    /// Test signing for constant-time execution
    #[cfg(feature = "constant-time-testing")]
    pub fn sign_test_constant_time(
        &self,
        message: &[u8],
        config: &crate::security::constant_time::ConstantTimeConfig,
    ) -> Result<crate::security::constant_time::ConstantTimeResult, CryptoError> {
        use crate::security::constant_time::verify_constant_time;
        
        let keypair = self.clone();
        let msg = message.to_vec();
        
        let operation = |_: &()| {
            let _ = keypair.sign(&msg);
        };
        
        let input_generator = || ();
        
        verify_constant_time(operation, input_generator, config)
    }

    /// Sign a message and compress the signature
    ///
    /// This method signs a message and then compresses the signature to reduce its size.
    /// It's useful for constrained environments where signature size matters.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `compression_level` - The compression level to use
    ///
    /// # Returns
    ///
    /// A compressed signature
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::dilithium::{DilithiumKeyPair, DilithiumVariant, CompressionLevel};
    ///
    /// // Generate a key pair
    /// let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
    ///
    /// // Sign and compress a message
    /// let message = b"Hello, world!";
    /// let compressed = key_pair.sign_compressed(message, CompressionLevel::Light).unwrap();
    ///
    /// // Verify the compressed signature
    /// assert!(key_pair.verify_compressed(message, &compressed).unwrap());
    /// ```
    pub fn sign_compressed(&self, message: &[u8], compression_level: CompressionLevel) -> Result<CompressedSignature, CryptoError> {
        // First sign the message normally
        let signature = self.sign(message)?;
        
        // Then compress the signature
        compress_signature(&signature, compression_level, self.algorithm)
    }
    
    /// Verify a compressed signature
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `compressed_signature` - The compressed signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::dilithium::{DilithiumKeyPair, DilithiumVariant, CompressionLevel};
    ///
    /// // Generate a key pair
    /// let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
    ///
    /// // Get the public key
    /// let public_key = key_pair.public_key();
    ///
    /// // Sign and compress a message
    /// let message = b"Hello, world!";
    /// let compressed = key_pair.sign_compressed(message, CompressionLevel::Light).unwrap();
    ///
    /// // Verify the compressed signature using just the public key
    /// let is_valid = public_key.verify_compressed(message, &compressed).unwrap();
    /// assert!(is_valid);
    /// ```
    pub fn verify_compressed(&self, message: &[u8], compressed_signature: &CompressedSignature) -> Result<bool, CryptoError> {
        // First decompress the signature
        let signature = decompress_signature(compressed_signature)?;
        
        // Then verify the signature
        self.verify(message, &signature)
    }
}

impl DilithiumPublicKey {
    /// Verify a signature on a message using this public key
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let alg = self.algorithm.oqs_algorithm();
        let dilithium = Sig::new(alg).map_err(|e| CryptoError::OqsError(e.to_string()))?;

        // Create OQS objects from bytes using the Sig instance
        let pk = dilithium
            .public_key_from_bytes(&self.public_key)
            .ok_or_else(|| {
                CryptoError::dilithium_error(
                    "Signature verification failed",
                    "Failed to create public key from bytes",
                    error_codes::DILITHIUM_SIGNING_FAILED,
                )
            })?;

        let sig = dilithium.signature_from_bytes(signature).ok_or_else(|| {
            CryptoError::dilithium_error(
                "Signature verification failed",
                "Failed to create signature from bytes",
                error_codes::DILITHIUM_SIGNING_FAILED,
            )
        })?;

        match dilithium.verify(message, &sig, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Serialize the public key to bytes
    ///
    /// # Returns
    ///
    /// The serialized public key or an error
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        bincode::serialize(self).map_err(|e| CryptoError::SerializationError(e.to_string()))
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
        bincode::deserialize(data).map_err(|e| CryptoError::SerializationError(e.to_string()))
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
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();

        utils::to_hex(&hash[0..8])
    }

    /// Test verification for constant-time execution
    #[cfg(feature = "constant-time-testing")]
    pub fn verify_test_constant_time(
        &self,
        message: &[u8],
        signature: &[u8],
        config: &crate::security::constant_time::ConstantTimeConfig,
    ) -> Result<crate::security::constant_time::ConstantTimeResult, CryptoError> {
        use crate::security::constant_time::verify_constant_time;
        
        let pubkey = self.clone();
        let msg = message.to_vec();
        let sig = signature.to_vec();
        
        let operation = |_: &()| {
            let _ = pubkey.verify(&msg, &sig);
        };
        
        let input_generator = || ();
        
        verify_constant_time(operation, input_generator, config)
    }

    /// Verify a compressed signature
    ///
    /// This method decompresses a signature and then verifies it against a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `compressed_signature` - The compressed signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::dilithium::{DilithiumKeyPair, DilithiumVariant, CompressionLevel};
    ///
    /// // Generate a key pair
    /// let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
    ///
    /// // Get the public key
    /// let public_key = key_pair.public_key();
    ///
    /// // Sign and compress a message
    /// let message = b"Hello, world!";
    /// let compressed = key_pair.sign_compressed(message, CompressionLevel::Light).unwrap();
    ///
    /// // Verify the compressed signature using just the public key
    /// let is_valid = public_key.verify_compressed(message, &compressed).unwrap();
    /// assert!(is_valid);
    /// ```
    pub fn verify_compressed(
        &self,
        message: &[u8],
        compressed_signature: &crate::dilithium::CompressedSignature,
    ) -> Result<bool, CryptoError> {
        // First decompress the signature
        let signature = crate::dilithium::decompress_signature(compressed_signature)?;
        
        // Then verify the signature
        self.verify(message, &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_key_generation() {
        let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.secret_key.is_empty());

        // Verify key sizes
        assert_eq!(
            key_pair.public_key.len(),
            DilithiumVariant::Dilithium3.public_key_size()
        );
        assert_eq!(
            key_pair.secret_key.len(),
            DilithiumVariant::Dilithium3.secret_key_size()
        );
    }

    #[test]
    fn test_sign_verify() {
        let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
        let message = b"This is a test message to sign";

        // Sign the message
        let signature = key_pair.sign(message).unwrap();

        // Verify the signature
        let is_valid = key_pair.verify(message, &signature).unwrap();
        assert!(is_valid);

        // Verify the signature with public key
        let pub_key = key_pair.public_key();
        let is_valid = pub_key.verify(message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
        let message = b"This is a test message to sign";

        // Sign the message
        let mut signature = key_pair.sign(message).unwrap();

        // Tamper with the signature
        if !signature.is_empty() {
            signature[0] ^= 0x01;
        }

        // Verify the signature
        let is_valid = key_pair.verify(message, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_wrong_message() {
        let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
        let message1 = b"This is the original message";
        let message2 = b"This is a different message";

        // Sign the original message
        let signature = key_pair.sign(message1).unwrap();

        // Verify the signature against the wrong message
        let is_valid = key_pair.verify(message2, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_serialization() {
        let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
        let serialized = key_pair.to_bytes().unwrap();
        let deserialized = DilithiumKeyPair::from_bytes(&serialized).unwrap();

        assert_eq!(key_pair.algorithm, deserialized.algorithm);
        assert_eq!(key_pair.public_key, deserialized.public_key);
        assert_eq!(key_pair.secret_key, deserialized.secret_key);
    }

    #[test]
    fn test_public_key_serialization() {
        let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
        let pub_key = key_pair.public_key();

        let serialized = pub_key.to_bytes().unwrap();
        let deserialized = DilithiumPublicKey::from_bytes(&serialized).unwrap();

        assert_eq!(pub_key.algorithm, deserialized.algorithm);
        assert_eq!(pub_key.public_key, deserialized.public_key);
    }

    #[test]
    fn test_public_key_fingerprint() {
        let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();
        let pub_key = key_pair.public_key();

        let fingerprint = pub_key.fingerprint();
        assert_eq!(fingerprint.len(), 16); // 8 bytes as hex = 16 chars
    }

    #[test]
    fn test_all_variants() {
        // Test all Dilithium variants
        for variant in [
            DilithiumVariant::Dilithium2,
            DilithiumVariant::Dilithium3,
            DilithiumVariant::Dilithium5,
        ]
        .iter()
        {
            let key_pair = DilithiumKeyPair::generate(*variant).unwrap();
            let message = b"Test message for all variants";

            let signature = key_pair.sign(message).unwrap();
            let is_valid = key_pair.verify(message, &signature).unwrap();

            assert!(is_valid);
            assert_eq!(key_pair.public_key.len(), variant.public_key_size());
            assert_eq!(key_pair.secret_key.len(), variant.secret_key_size());
        }
    }

    #[test]
    fn test_lean_dilithium() {
        let mut lean = LeanDilithium::new(DilithiumVariant::Dilithium2);
        let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium2).unwrap();

        let message = b"Test message for lean Dilithium";

        // Sign using lean implementation
        let signature = lean.sign(message, &key_pair.secret_key).unwrap();

        // Verify using lean implementation
        let is_valid = lean
            .verify(message, &signature, &key_pair.public_key)
            .unwrap();
        assert!(is_valid);

        // Test resource release
        lean.release_resources();
        assert!(lean.sig_instance.is_none());

        // Test functions still work after release
        let signature2 = lean.sign(message, &key_pair.secret_key).unwrap();
        let is_valid2 = lean
            .verify(message, &signature2, &key_pair.public_key)
            .unwrap();
        assert!(is_valid2);
    }

    #[test]
    fn test_variant_selection_for_constrained_environment() {
        // Test with different constraints
        assert_eq!(
            DilithiumVariant::for_constrained_environment(2, 8).unwrap(),
            DilithiumVariant::Dilithium2
        );

        assert_eq!(
            DilithiumVariant::for_constrained_environment(3, 12).unwrap(),
            DilithiumVariant::Dilithium3
        );

        assert_eq!(
            DilithiumVariant::for_constrained_environment(5, 16).unwrap(),
            DilithiumVariant::Dilithium5
        );

        // Test with insufficient memory
        assert!(DilithiumVariant::for_constrained_environment(2, 4).is_none());

        // Test with excess memory but minimum security level
        assert_eq!(
            DilithiumVariant::for_constrained_environment(3, 20).unwrap(),
            DilithiumVariant::Dilithium3
        );
    }

    #[test]
    fn test_streamlined_functions() {
        // Generate a key pair with the regular implementation for testing
        let key_pair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium2).unwrap();

        let message = b"Test message for streamlined functions";

        // Test lean_sign and lean_verify
        let signature = lean_sign(message, &key_pair.secret_key, key_pair.algorithm).unwrap();
        let is_valid = lean_verify(
            message,
            &signature,
            &key_pair.public_key,
            key_pair.algorithm,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_batch_verification() {
        // Generate a few key pairs
        let key_pair1 = DilithiumKeyPair::generate(DilithiumVariant::Dilithium2).unwrap();
        let key_pair2 = DilithiumKeyPair::generate(DilithiumVariant::Dilithium3).unwrap();

        // Create messages and signatures
        let message1 = b"Test message 1";
        let message2 = b"Test message 2";

        let signature1 = key_pair1.sign(message1).unwrap();
        let signature2 = key_pair2.sign(message2).unwrap();

        // Test batch verification with LeanDilithium
        let mut lean = LeanDilithium::new(DilithiumVariant::Dilithium2);

        let batch = vec![
            (
                message1 as &[u8],
                signature1.as_ref(),
                key_pair1.public_key.as_ref(),
            ),
            // This should fail (wrong key)
            (
                message2 as &[u8],
                signature2.as_ref(),
                key_pair1.public_key.as_ref(),
            ),
        ];

        let results = lean.verify_batch(&batch).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0]); // Valid
        assert!(!results[1]); // Invalid

        // Test lean_verify_batch with mixed variants
        let batch_mixed = vec![
            (
                message1 as &[u8],
                signature1.as_ref(),
                key_pair1.public_key.as_ref(),
                DilithiumVariant::Dilithium2,
            ),
            (
                message2 as &[u8],
                signature2.as_ref(),
                key_pair2.public_key.as_ref(),
                DilithiumVariant::Dilithium3,
            ),
            // This should fail (wrong variant)
            (
                message1 as &[u8],
                signature1.as_ref(),
                key_pair1.public_key.as_ref(),
                DilithiumVariant::Dilithium3,
            ),
        ];

        let results_mixed = lean_verify_batch(&batch_mixed).unwrap();
        assert_eq!(results_mixed.len(), 3);
        assert!(results_mixed[0]); // Valid
        assert!(results_mixed[1]); // Valid
        assert!(!results_mixed[2]); // Invalid (wrong variant)
    }
}
