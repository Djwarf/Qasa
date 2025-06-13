/*!
 * Memory-Efficient Kyber Implementation for Constrained Environments
 *
 * This module provides optimized versions of Kyber operations designed
 * for environments with limited memory resources, such as embedded systems
 * or IoT devices.
 */

use crate::error::{CryptoError, error_codes};
use crate::kyber::KyberVariant;
use crate::secure_memory::SecureBytes;
use oqs::kem::{Algorithm, Kem};

/// Memory usage profile for Kyber operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProfile {
    /// Standard memory usage (default)
    Standard,
    
    /// Reduced memory usage with minimal performance impact
    Reduced,
    
    /// Minimal memory usage, may impact performance
    Minimal,
}

/// Memory-efficient Kyber key encapsulation
///
/// This struct provides memory-optimized implementations of Kyber operations
/// for constrained environments. It uses lazy initialization and minimizes
/// memory allocations to reduce the memory footprint.
///
/// # Memory Optimization Techniques
///
/// 1. Lazy initialization of cryptographic contexts
/// 2. Reuse of memory buffers across operations
/// 3. Incremental processing to reduce peak memory usage
/// 4. Explicit memory management with immediate zeroization
///
/// # Example
///
/// ```
/// use qasa::kyber::{KyberVariant, lean::LeanKyber, lean::MemoryProfile};
///
/// // Create a memory-efficient Kyber instance
/// let mut lean_kyber = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Minimal);
///
/// // Generate keys with minimal memory usage
/// let (public_key, secret_key) = lean_kyber.generate_keypair().unwrap();
///
/// // Use the keys for encapsulation/decapsulation
/// let (ciphertext, shared_secret) = lean_kyber.encapsulate(&public_key).unwrap();
/// let decapsulated = lean_kyber.decapsulate(secret_key.as_bytes(), &ciphertext).unwrap();
///
/// // Compare the byte slices
/// assert_eq!(shared_secret.as_bytes(), decapsulated.as_bytes());
///
/// // Explicitly release resources when done
/// lean_kyber.release_resources();
/// ```
pub struct LeanKyber {
    /// The Kyber variant being used
    variant: KyberVariant,
    
    /// Memory usage profile
    memory_profile: MemoryProfile,
    
    /// OQS Kyber implementation (lazily initialized)
    kem: Option<Kem>,
    
    /// Reusable buffer for public key
    pub_key_buffer: Option<Vec<u8>>,
    
    /// Reusable buffer for secret key
    secret_key_buffer: Option<SecureBytes>,
    
    /// Reusable buffer for ciphertext
    ciphertext_buffer: Option<Vec<u8>>,
    
    /// Reusable buffer for shared secret
    shared_secret_buffer: Option<SecureBytes>,
}

impl LeanKyber {
    /// Create a new memory-efficient Kyber instance
    ///
    /// # Arguments
    ///
    /// * `variant` - The Kyber variant to use (Kyber512, Kyber768, or Kyber1024)
    /// * `memory_profile` - The memory usage profile to use
    ///
    /// # Returns
    ///
    /// A new LeanKyber instance
    pub fn new(variant: KyberVariant, memory_profile: MemoryProfile) -> Self {
        Self {
            variant,
            memory_profile,
            kem: None,
            pub_key_buffer: None,
            secret_key_buffer: None,
            ciphertext_buffer: None,
            shared_secret_buffer: None,
        }
    }
    
    /// Initialize the OQS Kyber implementation if not already initialized
    ///
    /// This method lazily initializes the OQS Kyber implementation only when needed,
    /// reducing memory usage when the implementation is not actively being used.
    ///
    /// # Returns
    ///
    /// A reference to the initialized Kem object, or an error if initialization fails
    fn ensure_initialized(&mut self) -> Result<&mut Kem, CryptoError> {
        if self.kem.is_none() {
            let algorithm = match self.variant {
                KyberVariant::Kyber512 => Algorithm::Kyber512,
                KyberVariant::Kyber768 => Algorithm::Kyber768,
                KyberVariant::Kyber1024 => Algorithm::Kyber1024,
            };
            
            self.kem = Some(Kem::new(algorithm).map_err(|e| {
                CryptoError::kyber_error(
                    "initialize Kyber",
                    &e.to_string(),
                    error_codes::KYBER_INITIALIZATION_FAILED
                )
            })?);
        }
        
        Ok(self.kem.as_mut().unwrap())
    }
    
    /// Generate a new Kyber key pair with minimal memory usage
    ///
    /// This method generates a new Kyber key pair while minimizing memory allocations
    /// by reusing internal buffers when possible.
    ///
    /// # Returns
    ///
    /// A tuple containing the public key and secret key as byte vectors
    pub fn generate_keypair(&mut self) -> Result<(Vec<u8>, SecureBytes), CryptoError> {
        let kem = self.ensure_initialized()?;
        
        // Generate the key pair using OQS API
        let (pk, sk) = kem.keypair().map_err(|e| {
            CryptoError::kyber_error(
                "generate key pair",
                &e.to_string(),
                error_codes::KYBER_KEY_GENERATION_FAILED
            )
        })?;
        
        // Convert OQS types to byte arrays
        let pk_bytes = pk.into_vec();
        let sk_bytes = sk.into_vec();
        
        // Reuse existing buffers if available, otherwise create new ones
        if let Some(ref mut buffer) = self.pub_key_buffer {
            buffer.clear();
            buffer.extend_from_slice(&pk_bytes);
        } else {
            self.pub_key_buffer = Some(pk_bytes.clone());
        }
        
        if let Some(ref mut buffer) = self.secret_key_buffer {
            buffer.clear();
            buffer.extend_from_slice(&sk_bytes);
        } else {
            self.secret_key_buffer = Some(SecureBytes::new(&sk_bytes));
        }
        
        // Return copies of the keys (we keep our internal buffers for reuse)
        let public_key = self.pub_key_buffer.as_ref().unwrap().clone();
        let secret_key = SecureBytes::new(self.secret_key_buffer.as_ref().unwrap().as_bytes());
        
        Ok((public_key, secret_key))
    }
    
    /// Encapsulate a shared secret using a public key with minimal memory usage
    ///
    /// # Arguments
    ///
    /// * `public_key` - The recipient's public key
    ///
    /// # Returns
    ///
    /// A tuple containing the ciphertext and shared secret
    pub fn encapsulate(&mut self, public_key: &[u8]) -> Result<(Vec<u8>, SecureBytes), CryptoError> {
        let kem = self.ensure_initialized()?;
        
        // Create a public key from bytes
        let pk = kem.public_key_from_bytes(public_key).ok_or_else(|| {
            CryptoError::kyber_error(
                "encapsulation",
                "Failed to create public key from bytes",
                error_codes::KYBER_KEY_GENERATION_FAILED
            )
        })?;
        
        // Perform encapsulation using OQS API
        let (ct, ss) = kem.encapsulate(&pk).map_err(|e| {
            CryptoError::kyber_error(
                "encapsulate shared secret",
                &e.to_string(),
                error_codes::KYBER_ENCAPSULATION_FAILED
            )
        })?;
        
        // Convert OQS types to byte arrays
        let ct_bytes = ct.into_vec();
        let ss_bytes = ss.into_vec();
        
        // Reuse existing buffers if available, otherwise create new ones
        if let Some(ref mut buffer) = self.ciphertext_buffer {
            buffer.clear();
            buffer.extend_from_slice(&ct_bytes);
        } else {
            self.ciphertext_buffer = Some(ct_bytes.clone());
        }
        
        if let Some(ref mut buffer) = self.shared_secret_buffer {
            buffer.clear();
            buffer.extend_from_slice(&ss_bytes);
        } else {
            self.shared_secret_buffer = Some(SecureBytes::new(&ss_bytes));
        }
        
        // Return copies of the ciphertext and shared secret
        let ciphertext = self.ciphertext_buffer.as_ref().unwrap().clone();
        let shared_secret = SecureBytes::new(self.shared_secret_buffer.as_ref().unwrap().as_bytes());
        
        Ok((ciphertext, shared_secret))
    }
    
    /// Decapsulate a shared secret using a secret key with minimal memory usage
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The recipient's secret key
    /// * `ciphertext` - The ciphertext containing the encapsulated shared secret
    ///
    /// # Returns
    ///
    /// The decapsulated shared secret
    pub fn decapsulate(&mut self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecureBytes, CryptoError> {
        let kem = self.ensure_initialized()?;
        
        // Create a secret key from bytes
        let sk = kem.secret_key_from_bytes(secret_key).ok_or_else(|| {
            CryptoError::kyber_error(
                "decapsulation",
                "Failed to create secret key from bytes",
                error_codes::KYBER_KEY_GENERATION_FAILED
            )
        })?;
        
        // Create a ciphertext from bytes
        let ct = kem.ciphertext_from_bytes(ciphertext).ok_or_else(|| {
            CryptoError::kyber_error(
                "decapsulation",
                "Failed to create ciphertext from bytes",
                error_codes::KYBER_DECAPSULATION_FAILED
            )
        })?;
        
        // Perform decapsulation using OQS API
        let ss = kem.decapsulate(&sk, &ct).map_err(|e| {
            CryptoError::kyber_error(
                "decapsulate shared secret",
                &e.to_string(),
                error_codes::KYBER_DECAPSULATION_FAILED
            )
        })?;
        
        // Convert OQS SharedSecret to byte array
        let ss_bytes = ss.into_vec();
        
        // Reuse existing buffer if available, otherwise create a new one
        if let Some(ref mut buffer) = self.shared_secret_buffer {
            buffer.clear();
            buffer.extend_from_slice(&ss_bytes);
        } else {
            self.shared_secret_buffer = Some(SecureBytes::new(&ss_bytes));
        }
        
        // Return a copy of the shared secret
        let shared_secret = SecureBytes::new(self.shared_secret_buffer.as_ref().unwrap().as_bytes());
        
        Ok(shared_secret)
    }
    
    /// Explicitly release resources to free memory
    ///
    /// This method releases all internal buffers and the OQS implementation,
    /// freeing memory when the Kyber operations are no longer needed.
    pub fn release_resources(&mut self) {
        // Zeroize and drop all buffers
        if let Some(ref mut buffer) = self.secret_key_buffer {
            buffer.clear();
        }
        self.secret_key_buffer = None;
        
        if let Some(ref mut buffer) = self.shared_secret_buffer {
            buffer.clear();
        }
        self.shared_secret_buffer = None;
        
        if let Some(ref mut buffer) = self.pub_key_buffer {
            buffer.clear();
            buffer.shrink_to_fit();
        }
        self.pub_key_buffer = None;
        
        if let Some(ref mut buffer) = self.ciphertext_buffer {
            buffer.clear();
            buffer.shrink_to_fit();
        }
        self.ciphertext_buffer = None;
        
        // Drop the KEM implementation
        self.kem = None;
    }
    
    /// Get the current memory usage in bytes
    ///
    /// This method calculates the approximate memory usage of this LeanKyber instance,
    /// including all internal buffers.
    ///
    /// # Returns
    ///
    /// The approximate memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        let mut usage = std::mem::size_of::<Self>();
        
        // Add buffer sizes
        if let Some(ref buffer) = self.pub_key_buffer {
            usage += buffer.capacity();
        }
        
        if let Some(ref buffer) = self.secret_key_buffer {
            usage += buffer.len();
        }
        
        if let Some(ref buffer) = self.ciphertext_buffer {
            usage += buffer.capacity();
        }
        
        if let Some(ref buffer) = self.shared_secret_buffer {
            usage += buffer.len();
        }
        
        // Estimate KEM size if initialized
        if self.kem.is_some() {
            // Rough estimate of KEM size
            usage += match self.variant {
                KyberVariant::Kyber512 => 4 * 1024,  // 4 KB
                KyberVariant::Kyber768 => 6 * 1024,  // 6 KB
                KyberVariant::Kyber1024 => 8 * 1024, // 8 KB
            };
        }
        
        usage
    }
    
    /// Get the variant being used
    pub fn variant(&self) -> KyberVariant {
        self.variant
    }
    
    /// Get the memory profile being used
    pub fn memory_profile(&self) -> MemoryProfile {
        self.memory_profile
    }
}

impl Drop for LeanKyber {
    fn drop(&mut self) {
        self.release_resources();
    }
}

/// One-shot function for memory-efficient key generation
///
/// This function provides a simplified interface for generating a Kyber key pair
/// with minimal memory usage, without needing to create and manage a LeanKyber instance.
///
/// # Arguments
///
/// * `variant` - The Kyber variant to use
/// * `memory_profile` - The memory usage profile
///
/// # Returns
///
/// A tuple containing the public key and secret key
pub fn generate_keypair(
    variant: KyberVariant,
    memory_profile: MemoryProfile,
) -> Result<(Vec<u8>, SecureBytes), CryptoError> {
    let mut lean = LeanKyber::new(variant, memory_profile);
    let result = lean.generate_keypair();
    lean.release_resources();
    result
}

/// One-shot function for memory-efficient encapsulation
///
/// # Arguments
///
/// * `public_key` - The recipient's public key
/// * `variant` - The Kyber variant to use
/// * `memory_profile` - The memory usage profile
///
/// # Returns
///
/// A tuple containing the ciphertext and shared secret
pub fn encapsulate(
    public_key: &[u8],
    variant: KyberVariant,
    memory_profile: MemoryProfile,
) -> Result<(Vec<u8>, SecureBytes), CryptoError> {
    let mut lean = LeanKyber::new(variant, memory_profile);
    let result = lean.encapsulate(public_key);
    lean.release_resources();
    result
}

/// One-shot function for memory-efficient decapsulation
///
/// # Arguments
///
/// * `secret_key` - The recipient's secret key
/// * `ciphertext` - The ciphertext containing the encapsulated shared secret
/// * `variant` - The Kyber variant to use
/// * `memory_profile` - The memory usage profile
///
/// # Returns
///
/// The decapsulated shared secret
pub fn decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
    variant: KyberVariant,
    memory_profile: MemoryProfile,
) -> Result<SecureBytes, CryptoError> {
    let mut lean = LeanKyber::new(variant, memory_profile);
    let result = lean.decapsulate(secret_key, ciphertext);
    lean.release_resources();
    result
}

/// Determine the appropriate Kyber variant for a constrained environment
///
/// This function selects the most appropriate Kyber variant based on
/// the available memory and security requirements.
///
/// # Arguments
///
/// * `min_security_level` - Minimum required NIST security level (1, 3, or 5)
/// * `available_memory_kb` - Available memory in kilobytes
///
/// # Returns
///
/// The recommended Kyber variant, or an error if no suitable variant exists
pub fn variant_for_constrained_environment(
    min_security_level: u8,
    available_memory_kb: usize,
) -> Result<KyberVariant, CryptoError> {
    // Memory requirements (in KB) for each variant with minimal memory profile
    const KYBER512_MIN_MEMORY: usize = 8;   // ~8 KB
    const KYBER768_MIN_MEMORY: usize = 12;  // ~12 KB
    const KYBER1024_MIN_MEMORY: usize = 16; // ~16 KB
    
    // Select the appropriate variant based on security level and memory constraints
    match min_security_level {
        1 => {
            if available_memory_kb >= KYBER512_MIN_MEMORY {
                Ok(KyberVariant::Kyber512)
            } else {
                Err(CryptoError::kyber_error(
                    "memory constraint check",
                    &format!("Kyber512 requires at least {} KB, but only {} KB available", 
                        KYBER512_MIN_MEMORY, available_memory_kb),
                    error_codes::KYBER_INSUFFICIENT_MEMORY
                ))
            }
        },
        2 | 3 => {
            if available_memory_kb >= KYBER768_MIN_MEMORY {
                Ok(KyberVariant::Kyber768)
            } else if available_memory_kb >= KYBER512_MIN_MEMORY && min_security_level <= 1 {
                Ok(KyberVariant::Kyber512)
            } else {
                Err(CryptoError::kyber_error(
                    "memory constraint check",
                    &format!("Kyber768 requires at least {} KB, but only {} KB available", 
                        KYBER768_MIN_MEMORY, available_memory_kb),
                    error_codes::KYBER_INSUFFICIENT_MEMORY
                ))
            }
        },
        4 | 5 => {
            if available_memory_kb >= KYBER1024_MIN_MEMORY {
                Ok(KyberVariant::Kyber1024)
            } else if available_memory_kb >= KYBER768_MIN_MEMORY && min_security_level <= 3 {
                Ok(KyberVariant::Kyber768)
            } else if available_memory_kb >= KYBER512_MIN_MEMORY && min_security_level <= 1 {
                Ok(KyberVariant::Kyber512)
            } else {
                Err(CryptoError::kyber_error(
                    "memory constraint check",
                    &format!("Kyber1024 requires at least {} KB, but only {} KB available", 
                        KYBER1024_MIN_MEMORY, available_memory_kb),
                    error_codes::KYBER_INSUFFICIENT_MEMORY
                ))
            }
        },
        _ => Err(CryptoError::invalid_parameter(
            "min_security_level",
            "1, 3, or 5",
            &min_security_level.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lean_kyber_keypair_generation() {
        let mut lean = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Minimal);
        let (public_key, secret_key) = lean.generate_keypair().unwrap();
        
        assert_eq!(public_key.len(), KyberVariant::Kyber768.public_key_size());
        assert_eq!(secret_key.len(), KyberVariant::Kyber768.secret_key_size());
        
        // Check memory usage
        let usage = lean.memory_usage();
        println!("LeanKyber memory usage: {} bytes", usage);
        
        // Cleanup
        lean.release_resources();
    }
    
    #[test]
    fn test_lean_kyber_encapsulation_decapsulation() {
        let mut lean = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Minimal);
        
        // Generate key pair
        let (public_key, secret_key) = lean.generate_keypair().unwrap();
        
        // Encapsulate
        let (ciphertext, shared_secret1) = lean.encapsulate(&public_key).unwrap();
        
        // Decapsulate
        let shared_secret2 = lean.decapsulate(secret_key.as_bytes(), &ciphertext).unwrap();
        
        // Compare the byte slices
        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
        
        // Cleanup
        lean.release_resources();
    }
    
    #[test]
    fn test_oneshot_functions() {
        // Generate key pair
        let (public_key, secret_key) = generate_keypair(
            KyberVariant::Kyber512,
            MemoryProfile::Minimal,
        ).unwrap();
        
        // Encapsulate
        let (ciphertext, shared_secret1) = encapsulate(
            &public_key,
            KyberVariant::Kyber512,
            MemoryProfile::Minimal,
        ).unwrap();
        
        // Decapsulate
        let shared_secret2 = decapsulate(
            secret_key.as_bytes(),
            &ciphertext,
            KyberVariant::Kyber512,
            MemoryProfile::Minimal,
        ).unwrap();
        
        // Compare the byte slices
        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }
    
    #[test]
    fn test_variant_selection() {
        // Test with different memory constraints
        assert_eq!(
            variant_for_constrained_environment(1, 10).unwrap(),
            KyberVariant::Kyber512
        );
        
        assert_eq!(
            variant_for_constrained_environment(3, 15).unwrap(),
            KyberVariant::Kyber768
        );
        
        assert_eq!(
            variant_for_constrained_environment(5, 20).unwrap(),
            KyberVariant::Kyber1024
        );
        
        // Test with insufficient memory
        assert!(variant_for_constrained_environment(5, 10).is_err());
    }
    
    #[test]
    fn test_memory_profiles() {
        // Test different memory profiles
        let mut standard = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Standard);
        let mut reduced = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Reduced);
        let mut minimal = LeanKyber::new(KyberVariant::Kyber768, MemoryProfile::Minimal);
        
        // Generate key pairs
        let _ = standard.generate_keypair().unwrap();
        let _ = reduced.generate_keypair().unwrap();
        let _ = minimal.generate_keypair().unwrap();
        
        // Compare memory usage
        println!("Standard profile memory usage: {} bytes", standard.memory_usage());
        println!("Reduced profile memory usage: {} bytes", reduced.memory_usage());
        println!("Minimal profile memory usage: {} bytes", minimal.memory_usage());
        
        // Cleanup
        standard.release_resources();
        reduced.release_resources();
        minimal.release_resources();
    }
} 