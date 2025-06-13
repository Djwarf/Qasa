// Secure Memory Test Vectors for Interoperability
// Test vectors for secure memory operations including memory locking and canary protection

use qasa::secure_memory::{LockedMemory, LockedBuffer, CanaryBuffer, with_secure_scope};
use rand::{Rng, SeedableRng};
use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};

/// Test vector structure for locked memory operations
#[derive(Debug, Serialize, Deserialize)]
pub struct LockedMemoryTestVector {
    pub data: Vec<u8>,
    pub expected_hash: Vec<u8>, // SHA3-256 hash of the data after operations
}

/// Test vector structure for canary buffer operations
#[derive(Debug, Serialize, Deserialize)]
pub struct CanaryBufferTestVector {
    pub data: Vec<u8>,
    pub canary_value: Vec<u8>,  // Changed from u64 to Vec<u8> to match API
    pub expected_hash: Vec<u8>, // SHA3-256 hash of the data after operations
}

/// Generate a test vector for locked memory
pub fn generate_locked_memory_vector(data: &[u8]) -> LockedMemoryTestVector {
    // Create a locked memory buffer with the data
    let mut locked = LockedMemory::new(data.len())
        .expect("Failed to create locked memory");
    
    // Copy data into locked buffer
    locked.as_mut_slice().copy_from_slice(data);
    
    // Perform some operations on the locked memory
    for i in 0..data.len() {
        if i % 2 == 0 {
            locked.as_mut_slice()[i] ^= 0x55; // XOR with 0x55 for even indices
        } else {
            locked.as_mut_slice()[i] ^= 0xAA; // XOR with 0xAA for odd indices
        }
    }
    
    // Calculate hash of the modified data
    let mut hasher = Sha3_256::new();
    hasher.update(locked.as_slice());
    let hash = hasher.finalize().to_vec();
    
    // Revert the operations to restore original data
    for i in 0..data.len() {
        if i % 2 == 0 {
            locked.as_mut_slice()[i] ^= 0x55;
        } else {
            locked.as_mut_slice()[i] ^= 0xAA;
        }
    }
    
    LockedMemoryTestVector {
        data: data.to_vec(),
        expected_hash: hash,
    }
}

/// Generate a test vector for canary buffer
pub fn generate_canary_buffer_vector(
    data: &[u8], 
    canary_pattern: &[u8]
) -> CanaryBufferTestVector {
    // Create a canary buffer with the data
    let mut canary_buffer = CanaryBuffer::new(data.len(), canary_pattern);
    
    // Copy data into canary buffer
    canary_buffer.as_mut_slice().copy_from_slice(data);
    
    // Perform some operations on the canary buffer
    for i in 0..data.len() {
        if i % 3 == 0 {
            canary_buffer.as_mut_slice()[i] ^= 0x33; // XOR with 0x33 for indices divisible by 3
        } else if i % 3 == 1 {
            canary_buffer.as_mut_slice()[i] ^= 0x66; // XOR with 0x66 for indices with remainder 1
        } else {
            canary_buffer.as_mut_slice()[i] ^= 0x99; // XOR with 0x99 for indices with remainder 2
        }
    }
    
    // Verify canaries are intact
    canary_buffer.verify()
        .expect("Canary verification failed");
    
    // Calculate hash of the modified data
    let mut hasher = Sha3_256::new();
    hasher.update(canary_buffer.as_slice());
    let hash = hasher.finalize().to_vec();
    
    // Revert the operations to restore original data
    for i in 0..data.len() {
        if i % 3 == 0 {
            canary_buffer.as_mut_slice()[i] ^= 0x33;
        } else if i % 3 == 1 {
            canary_buffer.as_mut_slice()[i] ^= 0x66;
        } else {
            canary_buffer.as_mut_slice()[i] ^= 0x99;
        }
    }
    
    CanaryBufferTestVector {
        data: data.to_vec(),
        canary_value: canary_pattern.to_vec(),
        expected_hash: hash,
    }
}

/// Standard test vectors for locked memory
pub fn standard_locked_memory_vectors() -> Vec<LockedMemoryTestVector> {
    let mut vectors = Vec::new();
    
    // Test vector 1: Basic data
    let data_1 = b"This is a test for locked memory";
    vectors.push(generate_locked_memory_vector(data_1));
    
    // Test vector 2: Binary data
    let data_2 = &[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];
    vectors.push(generate_locked_memory_vector(data_2));
    
    // Test vector 3: Large data
    let data_3 = vec![0x42; 1024]; // 1KB of 0x42 bytes
    vectors.push(generate_locked_memory_vector(&data_3));
    
    vectors
}

/// Standard test vectors for canary buffer
pub fn standard_canary_buffer_vectors() -> Vec<CanaryBufferTestVector> {
    let mut vectors = Vec::new();
    
    // Test vector 1: Basic data with default canary
    let data_1 = b"This is a test for canary buffer";
    let canary_1 = b"DEADBEEF";
    vectors.push(generate_canary_buffer_vector(data_1, canary_1));
    
    // Test vector 2: Binary data with custom canary
    let data_2 = &[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];
    let canary_2 = b"CAFEBABE";
    vectors.push(generate_canary_buffer_vector(data_2, canary_2));
    
    // Test vector 3: Large data with another custom canary
    let data_3 = vec![0x69; 1024]; // 1KB of 0x69 bytes
    let canary_3 = b"FEEDFACE";
    vectors.push(generate_canary_buffer_vector(&data_3, canary_3));
    
    vectors
}

/// Special case test vectors for secure memory
pub fn special_case_vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut vectors = Vec::new();
    
    // Special case 1: Empty data
    vectors.push((Vec::new(), b"DEADBEEF".to_vec()));
    
    // Special case 2: Single byte
    vectors.push((vec![0x42], b"CAFEBABE".to_vec()));
    
    // Special case 3: Alternating pattern
    let mut alternating = Vec::new();
    for i in 0..100 {
        alternating.push(if i % 2 == 0 { 0x55 } else { 0xAA });
    }
    vectors.push((alternating, b"FEEDFACE".to_vec()));
    
    vectors
}

/// Test vectors for secure scope operations
pub fn secure_scope_vectors() -> Vec<Vec<u8>> {
    let mut vectors = Vec::new();
    
    // Test vector 1: Basic data
    vectors.push(b"This is sensitive data for secure scope".to_vec());
    
    // Test vector 2: Binary data
    vectors.push(vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ]);
    
    // Test vector 3: Large data
    vectors.push(vec![0x42; 1024]); // 1KB of 0x42 bytes
    
    vectors
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_locked_memory_vectors() {
        let vectors = standard_locked_memory_vectors();
        
        for vector in vectors {
            // Create a locked memory buffer with the data
            let mut locked = LockedMemory::new(vector.data.len())
                .expect("Failed to create locked memory");
            
            // Copy data into locked memory
            locked.as_mut_slice().copy_from_slice(&vector.data);
            
            // Perform the same operations as in the vector generation
            for i in 0..vector.data.len() {
                if i % 2 == 0 {
                    locked.as_mut_slice()[i] ^= 0x55;
                } else {
                    locked.as_mut_slice()[i] ^= 0xAA;
                }
            }
            
            // Calculate hash of the modified data
            let mut hasher = Sha3_256::new();
            hasher.update(locked.as_slice());
            let hash = hasher.finalize().to_vec();
            
            // Verify hash matches expected hash
            assert_eq!(hash, vector.expected_hash, "Hash mismatch for locked memory");
        }
    }
    
    #[test]
    fn test_canary_buffer_vectors() {
        let vectors = standard_canary_buffer_vectors();
        
        for vector in vectors {
            // Create a canary buffer with the data
            let mut canary_buffer = CanaryBuffer::new(vector.data.len(), &vector.canary_value);
            
            // Copy data into canary buffer
            canary_buffer.as_mut_slice().copy_from_slice(&vector.data);
            
            // Perform the same operations as in the vector generation
            for i in 0..vector.data.len() {
                if i % 3 == 0 {
                    canary_buffer.as_mut_slice()[i] ^= 0x33;
                } else if i % 3 == 1 {
                    canary_buffer.as_mut_slice()[i] ^= 0x66;
                } else {
                    canary_buffer.as_mut_slice()[i] ^= 0x99;
                }
            }
            
            // Verify canaries are intact
            canary_buffer.verify()
                .expect("Canary verification failed");
            
            // Calculate hash of the modified data
            let mut hasher = Sha3_256::new();
            hasher.update(canary_buffer.as_slice());
            let hash = hasher.finalize().to_vec();
            
            // Verify hash matches expected hash
            assert_eq!(hash, vector.expected_hash, "Hash mismatch for canary buffer");
        }
    }
    
    #[test]
    fn test_special_cases() {
        let vectors = special_case_vectors();
        
        for (data, canary_value) in vectors {
            // Test with locked memory
            if let Ok(mut locked) = LockedMemory::new(data.len()) {
                if !data.is_empty() {
                    locked.as_mut_slice().copy_from_slice(&data);
                }
                // Just verify that operations don't panic
                for i in 0..data.len() {
                    locked.as_mut_slice()[i] ^= 0x42;
                }
            }
            
            // Test with canary buffer
            let canary_buffer = CanaryBuffer::new(data.len(), &canary_value);
            if !data.is_empty() {
                canary_buffer.as_mut_slice().copy_from_slice(&data);
            }
            // Verify canaries are intact
            assert!(canary_buffer.verify().is_ok(), "Canary verification failed for special case");
        }
    }
    
    #[test]
    fn test_secure_scope() {
        let vectors = secure_scope_vectors();
        
        for data in vectors {
            // Use secure scope to process sensitive data
            with_secure_scope(|scope| {
                // Allocate memory within the secure scope
                let mut buffer = scope.allocate(data.len())
                    .expect("Failed to allocate in secure scope");
                
                // Copy data into the secure buffer
                buffer.copy_from_slice(&data);
                
                // Perform some operations
                for i in 0..buffer.len() {
                    buffer[i] ^= 0x42;
                }
                
                // Verify we can read the data back
                for i in 0..buffer.len() {
                    assert_eq!(buffer[i], data[i] ^ 0x42, "Data mismatch in secure scope");
                }
                
                // Restore original data
                for i in 0..buffer.len() {
                    buffer[i] ^= 0x42;
                }
                
                // Verify data is restored
                for i in 0..buffer.len() {
                    assert_eq!(buffer[i], data[i], "Data not properly restored in secure scope");
                }
                
                Ok(())
            }).expect("Secure scope operation failed");
        }
    }
} 