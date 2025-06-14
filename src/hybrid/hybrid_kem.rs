//! Hybrid Key Encapsulation Mechanism (KEM)
//!
//! This module provides an implementation of hybrid KEMs that combine
//! classical and post-quantum algorithms for enhanced security.

use std::fmt::{self, Display};
use std::cmp::PartialEq;
use std::hash::{Hash, Hasher};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};
use arrayref::array_ref;

use crate::error::{CryptoError, CryptoResult};
use crate::kyber::{KyberKeyPair, KyberPublicKey, KyberVariant};
use crate::bike::{BikeKeyPair, BikePublicKey, BikeVariant};
use crate::secure_memory::SecureBytes;
use crate::utils;

/// Classical KEM algorithms for hybrid use
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClassicalKemAlgorithm {
    /// ECDH with X25519
    X25519,
    /// ECDH with P-256
    P256,
    /// RSA-2048
    Rsa2048,
    /// RSA-3072
    Rsa3072,
}

/// Post-quantum KEM algorithms for hybrid use
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PostQuantumKemAlgorithm {
    /// CRYSTALS-Kyber
    Kyber(KyberVariant),
    /// BIKE
    Bike(BikeVariant),
}

/// Hybrid KEM variant combining a classical and post-quantum algorithm
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HybridKemVariant {
    /// Classical algorithm component
    pub classical: ClassicalKemAlgorithm,
    /// Post-quantum algorithm component
    pub post_quantum: PostQuantumKemAlgorithm,
}

/// Hybrid KEM key pair for encapsulation and decapsulation
#[derive(Debug)]
pub struct HybridKemKeyPair {
    /// Classical key pair component
    pub classical_key: Vec<u8>,
    /// Post-quantum key pair component
    pub post_quantum_key: Vec<u8>,
    /// The hybrid algorithm variant
    pub algorithm: HybridKemVariant,
}

/// Hybrid KEM public key for encapsulation
pub struct HybridKemPublicKey {
    /// Classical public key component
    pub classical_key: Vec<u8>,
    /// Post-quantum public key component
    pub post_quantum_key: Vec<u8>,
    /// The hybrid algorithm variant
    pub algorithm: HybridKemVariant,
}

/// Hybrid KEM ciphertext containing both classical and post-quantum components
#[derive(Debug)]
pub struct HybridKemCiphertext {
    /// Classical ciphertext component
    pub classical_ciphertext: Vec<u8>,
    /// Post-quantum ciphertext component
    pub post_quantum_ciphertext: Vec<u8>,
    /// The hybrid algorithm variant
    pub algorithm: HybridKemVariant,
}

impl Display for ClassicalKemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClassicalKemAlgorithm::X25519 => write!(f, "X25519"),
            ClassicalKemAlgorithm::P256 => write!(f, "P-256"),
            ClassicalKemAlgorithm::Rsa2048 => write!(f, "RSA-2048"),
            ClassicalKemAlgorithm::Rsa3072 => write!(f, "RSA-3072"),
        }
    }
}

impl Display for PostQuantumKemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PostQuantumKemAlgorithm::Kyber(variant) => write!(f, "Kyber-{}", variant),
            PostQuantumKemAlgorithm::Bike(variant) => write!(f, "BIKE-{}", variant),
        }
    }
}

impl Display for HybridKemVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.classical, self.post_quantum)
    }
}

impl Zeroize for HybridKemKeyPair {
    fn zeroize(&mut self) {
        self.classical_key.zeroize();
        self.post_quantum_key.zeroize();
    }
}

impl Drop for HybridKemKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl HybridKemKeyPair {
    /// Generate a new hybrid KEM key pair
    pub fn generate(variant: HybridKemVariant) -> CryptoResult<Self> {
        // Generate the classical component
        let classical_key = match variant.classical {
            ClassicalKemAlgorithm::X25519 => {
                // Generate X25519 key pair
                let mut rng = rand::thread_rng();
                
                // Use the x25519 function directly
                let mut secret_key = [0u8; 32];
                rng.fill_bytes(&mut secret_key);
                // Apply clamping as per RFC 7748
                secret_key[0] &= 248;
                secret_key[31] &= 127;
                secret_key[31] |= 64;
                
                // Generate public key
                let public_key = x25519_dalek::x25519(secret_key, x25519_dalek::X25519_BASEPOINT_BYTES);
                
                // Combine secret and public key for storage
                let mut key_data = Vec::with_capacity(32 + 32);
                key_data.extend_from_slice(&secret_key);
                key_data.extend_from_slice(&public_key);
                key_data
            },
            ClassicalKemAlgorithm::P256 => {
                // Generate P-256 key pair using ring
                let rng = ring::rand::SystemRandom::new();
                let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                    &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &rng,
                ).map_err(|_| CryptoError::key_management_error(
                    "key_generation",
                    "Failed to generate P-256 key pair",
                    "ECDSA",
                ))?;
                
                pkcs8.as_ref().to_vec()
            },
            ClassicalKemAlgorithm::Rsa2048 | ClassicalKemAlgorithm::Rsa3072 => {
                // For RSA, use the rsa crate for key generation
                use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePrivateKey};
                use rand::rngs::OsRng;
                
                // Determine the key size
                let bits = match variant.classical {
                    ClassicalKemAlgorithm::Rsa2048 => 2048,
                    ClassicalKemAlgorithm::Rsa3072 => 3072,
                    _ => unreachable!(),
                };
                
                // Generate the RSA key pair
                let private_key = RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| {
                    CryptoError::key_management_error(
                        "RSA key generation",
                        &format!("Failed to generate RSA key: {}", e),
                        "RSA",
                    )
                })?;
                
                // Extract the public key
                let _public_key = RsaPublicKey::from(&private_key);
                
                // Convert to PKCS#8 format
                let pkcs8 = private_key.to_pkcs8_der().map_err(|e| {
                    CryptoError::key_management_error(
                        "RSA encoding",
                        &format!("Failed to encode RSA key: {}", e),
                        "RSA",
                    )
                })?;
                
                pkcs8.as_bytes().to_vec()
            },
        };
        
        // Generate the post-quantum component
        let post_quantum_key = match variant.post_quantum {
            PostQuantumKemAlgorithm::Kyber(kyber_variant) => {
                let key_pair = KyberKeyPair::generate(kyber_variant)?;
                key_pair.to_bytes()?
            },
            PostQuantumKemAlgorithm::Bike(bike_variant) => {
                let key_pair = BikeKeyPair::generate(bike_variant)?;
                key_pair.to_bytes()?
            },
        };
        
        Ok(Self {
            classical_key,
            post_quantum_key,
            algorithm: variant,
        })
    }
    
    /// Get the public key for encapsulation
    pub fn public_key(&self) -> CryptoResult<HybridKemPublicKey> {
        let (classical_public_key, post_quantum_public_key) = match self.algorithm.classical {
            ClassicalKemAlgorithm::X25519 => {
                // Extract public key from combined storage
                if self.classical_key.len() != 64 {
                    return Err(CryptoError::invalid_parameter(
                        "classical_key",
                        "64 bytes for X25519",
                        &format!("{} bytes", self.classical_key.len()),
                    ));
                }
                
                let public_key = self.classical_key[32..].to_vec();
                
                // Extract post-quantum public key based on algorithm
                let post_quantum_public_key = match self.algorithm.post_quantum {
                    PostQuantumKemAlgorithm::Kyber(kyber_variant) => {
                        let key_pair = KyberKeyPair::from_bytes(&self.post_quantum_key)?;
                        key_pair.public_key().to_bytes()?
                    },
                    PostQuantumKemAlgorithm::Bike(bike_variant) => {
                        let key_pair = BikeKeyPair::from_bytes(&self.post_quantum_key)?;
                        key_pair.public_key().to_bytes()?
                    },
                };
                
                (public_key, post_quantum_public_key)
            },
            ClassicalKemAlgorithm::P256 => {
                // Extract public key from PKCS#8 format
                // In a real implementation, we would parse the PKCS#8 format properly
                // For now, we'll use the entire PKCS#8 document as the public key
                let public_key = self.classical_key.clone();
                
                // Extract post-quantum public key based on algorithm
                let post_quantum_public_key = match self.algorithm.post_quantum {
                    PostQuantumKemAlgorithm::Kyber(kyber_variant) => {
                        let key_pair = KyberKeyPair::from_bytes(&self.post_quantum_key)?;
                        key_pair.public_key().to_bytes()?
                    },
                    PostQuantumKemAlgorithm::Bike(bike_variant) => {
                        let key_pair = BikeKeyPair::from_bytes(&self.post_quantum_key)?;
                        key_pair.public_key().to_bytes()?
                    },
                };
                
                (public_key, post_quantum_public_key)
            },
            ClassicalKemAlgorithm::Rsa2048 | ClassicalKemAlgorithm::Rsa3072 => {
                // Extract public key from PKCS#8 format
                use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{DecodePrivateKey, EncodePublicKey}};
                
                // Parse the private key from PKCS#8
                let private_key = RsaPrivateKey::from_pkcs8_der(&self.classical_key).map_err(|e| {
                    CryptoError::key_management_error(
                        "RSA decoding",
                        &format!("Failed to decode RSA private key: {}", e),
                        "RSA",
                    )
                })?;
                
                // Extract the public key
                let public_key = RsaPublicKey::from(&private_key);
                
                // Encode the public key in SPKI format
                let spki = public_key.to_public_key_der().map_err(|e| {
                    CryptoError::key_management_error(
                        "RSA encoding",
                        &format!("Failed to encode RSA public key: {}", e),
                        "RSA",
                    )
                })?;
                
                (spki.as_bytes().to_vec(), post_quantum_public_key)
            },
        };
        
        Ok(HybridKemPublicKey {
            classical_key: classical_public_key,
            post_quantum_key: post_quantum_public_key,
            algorithm: self.algorithm,
        })
    }
    
    /// Decapsulate a hybrid ciphertext to recover the shared secret
    pub fn decapsulate(&self, ciphertext: &HybridKemCiphertext) -> CryptoResult<Vec<u8>> {
        // Check that the algorithm matches
        if self.algorithm != ciphertext.algorithm {
            return Err(CryptoError::invalid_parameter(
                "ciphertext.algorithm",
                &format!("{}", self.algorithm),
                &format!("{}", ciphertext.algorithm),
            ));
        }
        
        // Decapsulate the classical component
        let classical_shared_secret = match self.algorithm.classical {
            ClassicalKemAlgorithm::X25519 => {
                // Extract secret key from combined storage
                if self.classical_key.len() != 64 {
                    return Err(CryptoError::invalid_parameter(
                        "classical_key",
                        "64 bytes for X25519",
                        &format!("{} bytes", self.classical_key.len()),
                    ));
                }
                
                let secret_key_bytes = &self.classical_key[0..32];
                let secret_key = *array_ref!(secret_key_bytes, 0, 32);
                
                // Check ciphertext size
                if ciphertext.classical_ciphertext.len() != 32 {
                    return Err(CryptoError::invalid_parameter(
                        "classical_ciphertext",
                        "32 bytes for X25519",
                        &format!("{} bytes", ciphertext.classical_ciphertext.len()),
                    ));
                }
                
                // Convert ciphertext to public key and perform DH
                let public_key_bytes = array_ref!(ciphertext.classical_ciphertext.as_slice(), 0, 32);
                let public_key = *public_key_bytes;
                
                // Compute shared secret using the x25519 function
                let shared_secret = x25519_dalek::x25519(secret_key, public_key);
                shared_secret.to_vec()
            },
            ClassicalKemAlgorithm::P256 => {
                // Parse the private key from PKCS#8
                let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
                    &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &self.classical_key
                ).map_err(|_| CryptoError::key_management_error(
                    "decapsulation",
                    "Failed to parse P-256 key pair",
                    "ECDSA",
                ))?;
                
                // For ECDH with P-256, we would:
                // 1. Extract the peer's public key from the ciphertext
                // 2. Compute the shared secret using ECDH
                
                // In Ring, there's no direct ECDH API, but we can use the agreement module
                let peer_public_key = ring::agreement::UnparsedPublicKey::new(
                    &ring::agreement::ECDH_P256,
                    &ciphertext.classical_ciphertext
                );
                
                // Create an ephemeral private key for the agreement
                let my_private_key = ring::agreement::EphemeralPrivateKey::generate(
                    &ring::agreement::ECDH_P256,
                    &ring::rand::SystemRandom::new()
                ).map_err(|_| CryptoError::key_management_error(
                    "decapsulation",
                    "Failed to generate ephemeral P-256 key",
                    "ECDH",
                ))?;
                
                // Compute the shared secret
                let shared_secret = ring::agreement::agree_ephemeral(
                    my_private_key,
                    &peer_public_key,
                    ring::error::Unspecified,
                    |shared_key_material| {
                        // Copy the shared key material to a new Vec
                        Ok(shared_key_material.to_vec())
                    }
                ).map_err(|_| CryptoError::key_management_error(
                    "decapsulation",
                    "Failed to compute P-256 shared secret",
                    "ECDH",
                ))?;
                
                shared_secret
            },
            ClassicalKemAlgorithm::Rsa2048 | ClassicalKemAlgorithm::Rsa3072 => {
                // Decrypt the ciphertext using RSA-OAEP
                use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, Oaep, Hash};
                use rand::rngs::OsRng;
                
                // Parse the private key from PKCS#8
                let private_key = RsaPrivateKey::from_pkcs8_der(&self.classical_key).map_err(|e| {
                    CryptoError::key_management_error(
                        "RSA decoding",
                        &format!("Failed to decode RSA private key: {}", e),
                        "RSA",
                    )
                })?;
                
                // Create a padding scheme (OAEP with SHA-256)
                let padding = Oaep::new::<sha2::Sha256>();
                
                // Decrypt the ciphertext
                let shared_secret = private_key.decrypt(
                    &padding, 
                    &ciphertext.classical_ciphertext
                ).map_err(|e| {
                    CryptoError::key_management_error(
                        "RSA-OAEP decryption",
                        &format!("Failed to decrypt RSA ciphertext: {}", e),
                        "RSA",
                    )
                })?;
                
                shared_secret
            },
        };
        
        // Decapsulate the post-quantum component
        let post_quantum_shared_secret = match self.algorithm.post_quantum {
            PostQuantumKemAlgorithm::Kyber(kyber_variant) => {
                let key_pair = KyberKeyPair::from_bytes(&self.post_quantum_key)?;
                key_pair.decapsulate(&ciphertext.post_quantum_ciphertext)?
            },
            PostQuantumKemAlgorithm::Bike(bike_variant) => {
                let key_pair = BikeKeyPair::from_bytes(&self.post_quantum_key)?;
                key_pair.decapsulate(&ciphertext.post_quantum_ciphertext)?
            },
        };
        
        // Combine the shared secrets using XOF
        let mut combined_secret = Vec::with_capacity(
            classical_shared_secret.len() + post_quantum_shared_secret.len()
        );
        combined_secret.extend_from_slice(&classical_shared_secret);
        combined_secret.extend_from_slice(&post_quantum_shared_secret);
        
        // Hash the combined secret to get the final shared secret
        let final_shared_secret = utils::sha256(&combined_secret);
        
        Ok(final_shared_secret)
    }
    
    /// Serialize the hybrid key pair to bytes
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut result = Vec::new();
        
        // Serialize the algorithm variant
        // Classical algorithm (1 byte)
        match self.algorithm.classical {
            ClassicalKemAlgorithm::X25519 => result.push(1),
            ClassicalKemAlgorithm::P256 => result.push(2),
            ClassicalKemAlgorithm::Rsa2048 => result.push(3),
            ClassicalKemAlgorithm::Rsa3072 => result.push(4),
        }
        
        // Post-quantum algorithm family (1 byte)
        match self.algorithm.post_quantum {
            PostQuantumKemAlgorithm::Kyber(_) => result.push(1),
            PostQuantumKemAlgorithm::Bike(_) => result.push(2),
        }
        
        // Post-quantum algorithm variant (1 byte)
        match self.algorithm.post_quantum {
            PostQuantumKemAlgorithm::Kyber(variant) => {
                match variant {
                    KyberVariant::Kyber512 => result.push(1),
                    KyberVariant::Kyber768 => result.push(2),
                    KyberVariant::Kyber1024 => result.push(3),
                }
            },
            PostQuantumKemAlgorithm::Bike(variant) => {
                match variant {
                    BikeVariant::Bike1Level1 => result.push(1),
                    BikeVariant::Bike1Level3 => result.push(3),
                    BikeVariant::Bike1Level5 => result.push(5),
                }
            },
        }
        
        // Serialize key lengths
        // Classical key length (2 bytes)
        result.push((self.classical_key.len() >> 8) as u8);
        result.push((self.classical_key.len() & 0xFF) as u8);
        
        // Post-quantum key length (2 bytes)
        result.push((self.post_quantum_key.len() >> 8) as u8);
        result.push((self.post_quantum_key.len() & 0xFF) as u8);
        
        // Serialize keys
        result.extend_from_slice(&self.classical_key);
        result.extend_from_slice(&self.post_quantum_key);
        
        Ok(result)
    }
    
    /// Deserialize a hybrid key pair from bytes
    pub fn from_bytes(data: &[u8]) -> CryptoResult<Self> {
        if data.len() < 7 {
            return Err(CryptoError::invalid_parameter(
                "data",
                "at least 7 bytes",
                &format!("{} bytes", data.len()),
            ));
        }
        
        // Parse algorithm variant
        let classical_alg = match data[0] {
            1 => ClassicalKemAlgorithm::X25519,
            2 => ClassicalKemAlgorithm::P256,
            3 => ClassicalKemAlgorithm::Rsa2048,
            4 => ClassicalKemAlgorithm::Rsa3072,
            _ => {
                return Err(CryptoError::invalid_parameter(
                    "classical_algorithm",
                    "1-4",
                    &format!("{}", data[0]),
                ));
            }
        };
        
        // Parse post-quantum algorithm family and variant
        let pq_alg = match data[1] {
            1 => {
                // Kyber
                match data[2] {
                    1 => PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber512),
                    2 => PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
                    3 => PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber1024),
                    _ => {
                        return Err(CryptoError::invalid_parameter(
                            "kyber_variant",
                            "1-3",
                            &format!("{}", data[2]),
                        ));
                    }
                }
            },
            2 => {
                // BIKE
                match data[2] {
                    1 => PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level1),
                    3 => PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level3),
                    5 => PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level5),
                    _ => {
                        return Err(CryptoError::invalid_parameter(
                            "bike_variant",
                            "1, 3, or 5",
                            &format!("{}", data[2]),
                        ));
                    }
                }
            },
            _ => {
                return Err(CryptoError::invalid_parameter(
                    "post_quantum_algorithm",
                    "1-2",
                    &format!("{}", data[1]),
                ));
            }
        };
        
        // Parse key lengths
        let classical_key_len = ((data[3] as usize) << 8) | (data[4] as usize);
        let pq_key_len = ((data[5] as usize) << 8) | (data[6] as usize);
        
        // Validate total length
        if data.len() != 7 + classical_key_len + pq_key_len {
            return Err(CryptoError::invalid_parameter(
                "data.len()",
                &format!("{}", 7 + classical_key_len + pq_key_len),
                &format!("{}", data.len()),
            ));
        }
        
        // Extract keys
        let classical_key = data[7..(7 + classical_key_len)].to_vec();
        let post_quantum_key = data[(7 + classical_key_len)..(7 + classical_key_len + pq_key_len)].to_vec();
        
        Ok(Self {
            classical_key,
            post_quantum_key,
            algorithm: HybridKemVariant {
                classical: classical_alg,
                post_quantum: pq_alg,
            },
        })
    }
}

impl HybridKemPublicKey {
    /// Encapsulate to generate a shared secret and ciphertext
    pub fn encapsulate(&self) -> CryptoResult<(HybridKemCiphertext, Vec<u8>)> {
        // Encapsulate with the classical component
        let (classical_ciphertext, classical_shared_secret) = match self.algorithm.classical {
            ClassicalKemAlgorithm::X25519 => {
                // Generate ephemeral key pair
                let mut rng = rand::thread_rng();
                let mut ephemeral_secret = [0u8; 32];
                rng.fill_bytes(&mut ephemeral_secret);
                // Apply clamping as per RFC 7748
                ephemeral_secret[0] &= 248;
                ephemeral_secret[31] &= 127;
                ephemeral_secret[31] |= 64;
                
                // Generate ephemeral public key
                let ephemeral_public = x25519_dalek::x25519(ephemeral_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
                
                // Convert public key from bytes
                if self.classical_key.len() != 32 {
                    return Err(CryptoError::invalid_parameter(
                        "classical_key",
                        "32 bytes for X25519",
                        &format!("{} bytes", self.classical_key.len()),
                    ));
                }
                
                let public_key_bytes = array_ref!(self.classical_key.as_slice(), 0, 32);
                let public_key = *public_key_bytes;
                
                // Compute shared secret
                let shared_secret = x25519_dalek::x25519(ephemeral_secret, public_key);
                
                // Return ephemeral public key as ciphertext and the shared secret
                (ephemeral_public.to_vec(), shared_secret.to_vec())
            },
            ClassicalKemAlgorithm::P256 => {
                // For P-256, we'll perform ECDH properly using the ring crate
                
                // Parse the peer's public key
                let peer_public_key = ring::agreement::UnparsedPublicKey::new(
                    &ring::agreement::ECDH_P256,
                    &self.classical_key
                );
                
                // Generate an ephemeral key pair
                let ephemeral_private_key = ring::agreement::EphemeralPrivateKey::generate(
                    &ring::agreement::ECDH_P256,
                    &ring::rand::SystemRandom::new()
                ).map_err(|_| CryptoError::key_management_error(
                    "encapsulation",
                    "Failed to generate ephemeral P-256 key",
                    "ECDH",
                ))?;
                
                // Get the public key to use as ciphertext
                let ephemeral_public_key_bytes = ephemeral_private_key.compute_public_key()
                    .map_err(|_| CryptoError::key_management_error(
                        "encapsulation",
                        "Failed to compute P-256 public key",
                        "ECDH",
                    ))?;
                
                // Compute the shared secret
                let shared_secret = ring::agreement::agree_ephemeral(
                    ephemeral_private_key,
                    &peer_public_key,
                    ring::error::Unspecified,
                    |shared_key_material| {
                        // Copy the shared key material to a new Vec
                        Ok(shared_key_material.to_vec())
                    }
                ).map_err(|_| CryptoError::key_management_error(
                    "encapsulation",
                    "Failed to compute P-256 shared secret",
                    "ECDH",
                ))?;
                
                (ephemeral_public_key_bytes.as_ref().to_vec(), shared_secret)
            },
            ClassicalKemAlgorithm::Rsa2048 | ClassicalKemAlgorithm::Rsa3072 => {
                // Encrypt a random secret using RSA-OAEP
                use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, Oaep, Hash};
                use rand::{rngs::OsRng, RngCore};
                
                // Generate a random shared secret
                let mut shared_secret = vec![0u8; 32]; // 256-bit shared secret
                OsRng.fill_bytes(&mut shared_secret);
                
                // Parse the public key from SPKI format
                let public_key = RsaPublicKey::from_public_key_der(&self.classical_key).map_err(|e| {
                    CryptoError::key_management_error(
                        "RSA decoding",
                        &format!("Failed to decode RSA public key: {}", e),
                        "RSA",
                    )
                })?;
                
                // Create a padding scheme (OAEP with SHA-256)
                let padding = Oaep::new::<sha2::Sha256>();
                
                // Encrypt the shared secret
                let ciphertext = public_key.encrypt(&mut OsRng, &padding, &shared_secret).map_err(|e| {
                    CryptoError::key_management_error(
                        "RSA-OAEP encryption",
                        &format!("Failed to encrypt shared secret: {}", e),
                        "RSA",
                    )
                })?;
                
                (ciphertext, shared_secret)
            },
        };
        
        // Encapsulate with the post-quantum component
        let (post_quantum_ciphertext, post_quantum_shared_secret) = match self.algorithm.post_quantum {
            PostQuantumKemAlgorithm::Kyber(kyber_variant) => {
                let public_key = KyberPublicKey::from_bytes(&self.post_quantum_key)?;
                public_key.encapsulate()?
            },
            PostQuantumKemAlgorithm::Bike(bike_variant) => {
                let public_key = BikePublicKey::from_bytes(&self.post_quantum_key)?;
                public_key.encapsulate()?
            },
        };
        
        // Create the hybrid ciphertext
        let ciphertext = HybridKemCiphertext {
            classical_ciphertext,
            post_quantum_ciphertext,
            algorithm: self.algorithm,
        };
        
        // Combine the shared secrets using XOF
        let mut combined_secret = Vec::with_capacity(
            classical_shared_secret.len() + post_quantum_shared_secret.len()
        );
        combined_secret.extend_from_slice(&classical_shared_secret);
        combined_secret.extend_from_slice(&post_quantum_shared_secret);
        
        // Hash the combined secret to get the final shared secret
        let final_shared_secret = utils::sha256(&combined_secret);
        
        Ok((ciphertext, final_shared_secret))
    }
    
    /// Serialize the hybrid public key to bytes
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut result = Vec::new();
        
        // Serialize the algorithm variant
        // Classical algorithm (1 byte)
        match self.algorithm.classical {
            ClassicalKemAlgorithm::X25519 => result.push(1),
            ClassicalKemAlgorithm::P256 => result.push(2),
            ClassicalKemAlgorithm::Rsa2048 => result.push(3),
            ClassicalKemAlgorithm::Rsa3072 => result.push(4),
        }
        
        // Post-quantum algorithm family (1 byte)
        match self.algorithm.post_quantum {
            PostQuantumKemAlgorithm::Kyber(_) => result.push(1),
            PostQuantumKemAlgorithm::Bike(_) => result.push(2),
        }
        
        // Post-quantum algorithm variant (1 byte)
        match self.algorithm.post_quantum {
            PostQuantumKemAlgorithm::Kyber(variant) => {
                match variant {
                    KyberVariant::Kyber512 => result.push(1),
                    KyberVariant::Kyber768 => result.push(2),
                    KyberVariant::Kyber1024 => result.push(3),
                }
            },
            PostQuantumKemAlgorithm::Bike(variant) => {
                match variant {
                    BikeVariant::Bike1Level1 => result.push(1),
                    BikeVariant::Bike1Level3 => result.push(3),
                    BikeVariant::Bike1Level5 => result.push(5),
                }
            },
        }
        
        // Serialize key lengths
        // Classical key length (2 bytes)
        result.push((self.classical_key.len() >> 8) as u8);
        result.push((self.classical_key.len() & 0xFF) as u8);
        
        // Post-quantum key length (2 bytes)
        result.push((self.post_quantum_key.len() >> 8) as u8);
        result.push((self.post_quantum_key.len() & 0xFF) as u8);
        
        // Serialize keys
        result.extend_from_slice(&self.classical_key);
        result.extend_from_slice(&self.post_quantum_key);
        
        Ok(result)
    }
    
    /// Deserialize a hybrid public key from bytes
    pub fn from_bytes(data: &[u8]) -> CryptoResult<Self> {
        if data.len() < 7 {
            return Err(CryptoError::invalid_parameter(
                "data",
                "at least 7 bytes",
                &format!("{} bytes", data.len()),
            ));
        }
        
        // Parse algorithm variant
        let classical_alg = match data[0] {
            1 => ClassicalKemAlgorithm::X25519,
            2 => ClassicalKemAlgorithm::P256,
            3 => ClassicalKemAlgorithm::Rsa2048,
            4 => ClassicalKemAlgorithm::Rsa3072,
            _ => {
                return Err(CryptoError::invalid_parameter(
                    "classical_algorithm",
                    "1-4",
                    &format!("{}", data[0]),
                ));
            }
        };
        
        // Parse post-quantum algorithm family and variant
        let pq_alg = match data[1] {
            1 => {
                // Kyber
                match data[2] {
                    1 => PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber512),
                    2 => PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
                    3 => PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber1024),
                    _ => {
                        return Err(CryptoError::invalid_parameter(
                            "kyber_variant",
                            "1-3",
                            &format!("{}", data[2]),
                        ));
                    }
                }
            },
            2 => {
                // BIKE
                match data[2] {
                    1 => PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level1),
                    3 => PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level3),
                    5 => PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level5),
                    _ => {
                        return Err(CryptoError::invalid_parameter(
                            "bike_variant",
                            "1, 3, or 5",
                            &format!("{}", data[2]),
                        ));
                    }
                }
            },
            _ => {
                return Err(CryptoError::invalid_parameter(
                    "post_quantum_algorithm",
                    "1-2",
                    &format!("{}", data[1]),
                ));
            }
        };
        
        // Parse key lengths
        let classical_key_len = ((data[3] as usize) << 8) | (data[4] as usize);
        let pq_key_len = ((data[5] as usize) << 8) | (data[6] as usize);
        
        // Validate total length
        if data.len() != 7 + classical_key_len + pq_key_len {
            return Err(CryptoError::invalid_parameter(
                "data.len()",
                &format!("{}", 7 + classical_key_len + pq_key_len),
                &format!("{}", data.len()),
            ));
        }
        
        // Extract keys
        let classical_key = data[7..(7 + classical_key_len)].to_vec();
        let post_quantum_key = data[(7 + classical_key_len)..(7 + classical_key_len + pq_key_len)].to_vec();
        
        Ok(Self {
            classical_key,
            post_quantum_key,
            algorithm: HybridKemVariant {
                classical: classical_alg,
                post_quantum: pq_alg,
            },
        })
    }
    
    /// Calculate a fingerprint of the public key
    pub fn fingerprint(&self) -> String {
        // Combine both public keys
        let mut combined = Vec::with_capacity(
            self.classical_key.len() + self.post_quantum_key.len()
        );
        combined.extend_from_slice(&self.classical_key);
        combined.extend_from_slice(&self.post_quantum_key);
        
        // Calculate SHA-256 hash of the combined key
        let hash = utils::sha256(&combined);
        
        // Take first 8 bytes and convert to hex
        let mut fingerprint = String::new();
        for &byte in hash.iter().take(8) {
            fingerprint.push_str(&format!("{:02x}", byte));
        }
        
        fingerprint
    }
}

impl HybridKemCiphertext {
    /// Create a new hybrid KEM ciphertext
    pub fn new(
        classical_ciphertext: Vec<u8>,
        post_quantum_ciphertext: Vec<u8>,
        algorithm: HybridKemVariant,
    ) -> Self {
        Self {
            classical_ciphertext,
            post_quantum_ciphertext,
            algorithm,
        }
    }
    
    /// Serialize the hybrid ciphertext to bytes
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut result = Vec::new();
        
        // Serialize the algorithm variant
        // Classical algorithm (1 byte)
        match self.algorithm.classical {
            ClassicalKemAlgorithm::X25519 => result.push(1),
            ClassicalKemAlgorithm::P256 => result.push(2),
            ClassicalKemAlgorithm::Rsa2048 => result.push(3),
            ClassicalKemAlgorithm::Rsa3072 => result.push(4),
        }
        
        // Post-quantum algorithm family (1 byte)
        match self.algorithm.post_quantum {
            PostQuantumKemAlgorithm::Kyber(_) => result.push(1),
            PostQuantumKemAlgorithm::Bike(_) => result.push(2),
        }
        
        // Post-quantum algorithm variant (1 byte)
        match self.algorithm.post_quantum {
            PostQuantumKemAlgorithm::Kyber(variant) => {
                match variant {
                    KyberVariant::Kyber512 => result.push(1),
                    KyberVariant::Kyber768 => result.push(2),
                    KyberVariant::Kyber1024 => result.push(3),
                }
            },
            PostQuantumKemAlgorithm::Bike(variant) => {
                match variant {
                    BikeVariant::Bike1Level1 => result.push(1),
                    BikeVariant::Bike1Level3 => result.push(3),
                    BikeVariant::Bike1Level5 => result.push(5),
                }
            },
        }
        
        // Serialize ciphertext lengths
        // Classical ciphertext length (2 bytes)
        result.push((self.classical_ciphertext.len() >> 8) as u8);
        result.push((self.classical_ciphertext.len() & 0xFF) as u8);
        
        // Post-quantum ciphertext length (2 bytes)
        result.push((self.post_quantum_ciphertext.len() >> 8) as u8);
        result.push((self.post_quantum_ciphertext.len() & 0xFF) as u8);
        
        // Serialize ciphertexts
        result.extend_from_slice(&self.classical_ciphertext);
        result.extend_from_slice(&self.post_quantum_ciphertext);
        
        Ok(result)
    }
    
    /// Deserialize a hybrid ciphertext from bytes
    pub fn from_bytes(data: &[u8]) -> CryptoResult<Self> {
        if data.len() < 7 {
            return Err(CryptoError::invalid_parameter(
                "data",
                "at least 7 bytes",
                &format!("{} bytes", data.len()),
            ));
        }
        
        // Parse algorithm variant
        let classical_alg = match data[0] {
            1 => ClassicalKemAlgorithm::X25519,
            2 => ClassicalKemAlgorithm::P256,
            3 => ClassicalKemAlgorithm::Rsa2048,
            4 => ClassicalKemAlgorithm::Rsa3072,
            _ => {
                return Err(CryptoError::invalid_parameter(
                    "classical_algorithm",
                    "1-4",
                    &format!("{}", data[0]),
                ));
            }
        };
        
        // Parse post-quantum algorithm family and variant
        let pq_alg = match data[1] {
            1 => {
                // Kyber
                match data[2] {
                    1 => PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber512),
                    2 => PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber768),
                    3 => PostQuantumKemAlgorithm::Kyber(KyberVariant::Kyber1024),
                    _ => {
                        return Err(CryptoError::invalid_parameter(
                            "kyber_variant",
                            "1-3",
                            &format!("{}", data[2]),
                        ));
                    }
                }
            },
            2 => {
                // BIKE
                match data[2] {
                    1 => PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level1),
                    3 => PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level3),
                    5 => PostQuantumKemAlgorithm::Bike(BikeVariant::Bike1Level5),
                    _ => {
                        return Err(CryptoError::invalid_parameter(
                            "bike_variant",
                            "1, 3, or 5",
                            &format!("{}", data[2]),
                        ));
                    }
                }
            },
            _ => {
                return Err(CryptoError::invalid_parameter(
                    "post_quantum_algorithm",
                    "1-2",
                    &format!("{}", data[1]),
                ));
            }
        };
        
        // Parse ciphertext lengths
        let classical_ct_len = ((data[3] as usize) << 8) | (data[4] as usize);
        let pq_ct_len = ((data[5] as usize) << 8) | (data[6] as usize);
        
        // Validate total length
        if data.len() != 7 + classical_ct_len + pq_ct_len {
            return Err(CryptoError::invalid_parameter(
                "data.len()",
                &format!("{}", 7 + classical_ct_len + pq_ct_len),
                &format!("{}", data.len()),
            ));
        }
        
        // Extract ciphertexts
        let classical_ciphertext = data[7..(7 + classical_ct_len)].to_vec();
        let post_quantum_ciphertext = data[(7 + classical_ct_len)..(7 + classical_ct_len + pq_ct_len)].to_vec();
        
        Ok(Self {
            classical_ciphertext,
            post_quantum_ciphertext,
            algorithm: HybridKemVariant {
                classical: classical_alg,
                post_quantum: pq_alg,
            },
        })
    }
    
    /// Get the total size of the ciphertext in bytes
    pub fn size(&self) -> usize {
        self.classical_ciphertext.len() + self.post_quantum_ciphertext.len()
    }
    
    /// Get the size of the classical component in bytes
    pub fn classical_size(&self) -> usize {
        self.classical_ciphertext.len()
    }
    
    /// Get the size of the post-quantum component in bytes
    pub fn post_quantum_size(&self) -> usize {
        self.post_quantum_ciphertext.len()
    }
}
