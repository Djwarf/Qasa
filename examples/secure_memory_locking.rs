use qasa::secure_memory::{LockedBuffer, LockedMemory, SecureBytes};
use qasa::error::CryptoError;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Secure Memory Locking Example");
    println!("============================\n");

    // Example 1: Using LockedMemory directly
    println!("Example 1: Using LockedMemory directly");
    match LockedMemory::new(1024) {
        Ok(mut locked_memory) => {
            println!("✅ Successfully allocated and locked 1024 bytes of memory");
            println!("   Memory locked: {}", if locked_memory.is_locked() { "Yes" } else { "No (permission denied)" });
            
            // Write some data to the memory
            let slice = locked_memory.as_mut_slice();
            for i in 0..slice.len().min(64) {
                slice[i] = (i % 256) as u8;
            }
            
            // Create a copy of the first 16 bytes for display
            let first_bytes: Vec<u8> = slice[..16.min(slice.len())].to_vec();
            println!("   First 16 bytes: {:?}", first_bytes);
            println!("   Memory will be automatically zeroed and unlocked when dropped");
        },
        Err(e) => {
            println!("❌ Failed to lock memory: {}", e);
            println!("   This is expected on systems without appropriate permissions");
            println!("   Try running with sudo for successful memory locking");
        }
    }
    println!();

    // Example 2: Using LockedBuffer for sensitive data
    println!("Example 2: Using LockedBuffer for sensitive data");
    let sensitive_data = b"TOP SECRET: Encryption key for quantum-resistant communications";
    
    match LockedBuffer::new(sensitive_data) {
        Ok(buffer) => {
            println!("✅ Successfully created locked buffer with sensitive data");
            println!("   Memory locked: {}", if buffer.is_locked() { "Yes" } else { "No (permission denied)" });
            println!("   Buffer length: {} bytes", buffer.len());
            println!("   Data: {}", std::str::from_utf8(buffer.as_slice()).unwrap());
            println!("   Memory will be automatically zeroed and unlocked when dropped");
        },
        Err(e) => {
            println!("❌ Failed to create locked buffer: {}", e);
            println!("   This is expected on systems without appropriate permissions");
            println!("   Falling back to SecureBytes (which zeroes memory but doesn't prevent swapping)");
            
            // Fallback to SecureBytes
            let secure_bytes = SecureBytes::new(sensitive_data);
            println!("   Created SecureBytes with sensitive data");
            println!("   Data: {}", std::str::from_utf8(secure_bytes.as_bytes()).unwrap());
        }
    }
    println!();

    // Example 3: Comparing memory usage patterns
    println!("Example 3: Memory usage patterns for sensitive data");
    println!("   1. Regular Vec<u8>: Data remains in memory until dropped, may be swapped to disk");
    println!("   2. SecureBytes: Data is zeroed when dropped, but may be swapped to disk");
    println!("   3. LockedBuffer: Data is locked in RAM and zeroed when dropped");
    
    // Create a key with LockedBuffer if possible, otherwise fall back to SecureBytes
    let key_data = b"0123456789ABCDEF0123456789ABCDEF"; // 32-byte AES key
    let key = create_secure_key(key_data)?;
    
    println!("\n✅ Created secure key using: {}", key.name());
    println!("   Key will be securely erased from memory when no longer needed");
    
    // Use the key for some operation
    println!("   Using key for encryption...");
    // In a real application, you would use this key for cryptographic operations
    
    println!("\nMemory security best practices:");
    println!("   1. Use LockedMemory/LockedBuffer when highest security is required");
    println!("   2. Fall back to SecureBytes when memory locking is not available");
    println!("   3. Always ensure sensitive data is zeroed after use");
    println!("   4. Be aware of memory locking permission requirements");
    println!("   5. Consider increasing system limits for locked memory on production systems");
    
    Ok(())
}

// A trait for secure key storage
trait SecureKeyStorage {
    fn as_bytes(&self) -> &[u8];
    fn name(&self) -> &str;
}

// Implementation for LockedBuffer
impl SecureKeyStorage for LockedBuffer {
    fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }
    
    fn name(&self) -> &str {
        "LockedBuffer (memory locked in RAM)"
    }
}

// Implementation for SecureBytes
impl SecureKeyStorage for SecureBytes {
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
    
    fn name(&self) -> &str {
        "SecureBytes (memory zeroed when dropped)"
    }
}

// Create the most secure key storage available on this system
fn create_secure_key(key_data: &[u8]) -> Result<Box<dyn SecureKeyStorage>, CryptoError> {
    // Try to create a LockedBuffer first
    match LockedBuffer::new(key_data) {
        Ok(buffer) => Ok(Box::new(buffer) as Box<dyn SecureKeyStorage>),
        Err(_) => {
            // Fall back to SecureBytes if memory locking fails
            Ok(Box::new(SecureBytes::new(key_data)) as Box<dyn SecureKeyStorage>)
        }
    }
} 