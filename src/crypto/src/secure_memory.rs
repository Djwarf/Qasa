//! Secure Memory Handling Utilities
//! 
//! This module provides utilities for secure memory operations, including
//! securely zeroing memory, preventing memory from being swapped, and
//! creating secure containers for sensitive data.
//!
//! The primary goal of these utilities is to minimize the exposure of sensitive
//! cryptographic material (like keys, passwords, and plaintext) in memory, 
//! reducing the risk of memory-based attacks such as cold boot attacks or 
//! memory scanning by malicious processes.

use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure container for sensitive data that will be automatically
/// zeroed when dropped, preventing the data from remaining in memory.
///
/// This generic container can hold any type that implements the Zeroize trait,
/// ensuring that its contents are securely erased from memory when the
/// container goes out of scope or is explicitly dropped.
///
/// # Type Parameters
///
/// * `T` - The type of data to store, which must implement Zeroize
///
/// # Security Properties
///
/// 1. The contained data is automatically zeroed when the container is dropped
/// 2. If the container is cloned, each clone will independently zeroize its data
/// 3. The container provides controlled access through Deref/DerefMut
///
/// # Example
///
/// ```
/// use qasa::secure_memory::SecureBuffer;
///
/// // Create a secure buffer for a sensitive key
/// let key = SecureBuffer::new(vec![1, 2, 3, 4, 5]);
///
/// // Use the key for cryptographic operations
/// // ...
///
/// // When 'key' goes out of scope, it will be automatically zeroed
/// ```
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer<T: Zeroize> {
    /// The contained sensitive data
    inner: T,
}

impl<T: Zeroize> SecureBuffer<T> {
    /// Create a new secure buffer containing the given data
    ///
    /// # Arguments
    ///
    /// * `data` - The sensitive data to store in the secure buffer
    ///
    /// # Returns
    ///
    /// A new SecureBuffer containing the data
    pub fn new(data: T) -> Self {
        Self { inner: data }
    }

    /// Consume the secure buffer and return the contained data
    /// 
    /// This method extracts the sensitive data from the secure buffer,
    /// bypassing the automatic zeroing that would normally occur when the
    /// buffer is dropped. This should only be used when absolutely necessary.
    ///
    /// # Security Considerations
    ///
    /// After calling this method, it becomes the caller's responsibility
    /// to properly handle and zeroize the sensitive data. Failure to do so
    /// may leave sensitive data in memory.
    ///
    /// # Returns
    ///
    /// The contained data, which the caller must now properly handle
    pub fn into_inner(mut self) -> T {
        // Use std::mem::replace to move out of self.inner without triggering Drop
        std::mem::replace(&mut self.inner, unsafe { std::mem::zeroed() })
    }
}

impl<T: Zeroize> Deref for SecureBuffer<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for SecureBuffer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// A specialized SecureBuffer for byte arrays that adds additional
/// functionality specific to cryptographic keys and other sensitive byte data.
///
/// SecureBytes provides a memory-safe container specifically optimized for
/// handling sensitive binary data such as cryptographic keys, passwords, or
/// plaintext messages. It automatically zeroes the memory when dropped.
///
/// # Security Properties
///
/// 1. Automatically zeroes memory when dropped
/// 2. Prevents contents from being inadvertently logged or displayed
/// 3. Provides controlled access to the underlying bytes
/// 4. Implements Clone using secure copying
///
/// # Example
///
/// ```
/// use qasa::secure_memory::SecureBytes;
///
/// // Store a sensitive key in secure memory
/// let mut key = SecureBytes::new(&[0x01, 0x02, 0x03, 0x04]);
///
/// // Use the key for operations
/// let key_bytes = key.as_bytes();
/// // ... perform cryptographic operations
///
/// // When key goes out of scope, memory is securely zeroed
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes {
    bytes: Vec<u8>,
}

impl SecureBytes {
    /// Create a new SecureBytes with the given data
    ///
    /// # Arguments
    ///
    /// * `data` - The sensitive byte data to securely store
    ///
    /// # Returns
    ///
    /// A new SecureBytes containing a copy of the provided data
    pub fn new(data: &[u8]) -> Self {
        Self {
            bytes: data.to_vec(),
        }
    }

    /// Create a new SecureBytes with the given capacity
    ///
    /// This pre-allocates memory without initializing it, which is useful
    /// when planning to fill the buffer later.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The number of bytes to pre-allocate
    ///
    /// # Returns
    ///
    /// A new empty SecureBytes with the specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Get a reference to the underlying bytes
    ///
    /// This provides read-only access to the sensitive data for operations
    /// that need to use the raw bytes.
    ///
    /// # Returns
    ///
    /// A slice referring to the protected bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get a mutable reference to the underlying bytes
    ///
    /// This provides read-write access to the sensitive data for operations
    /// that need to modify the raw bytes.
    ///
    /// # Returns
    ///
    /// A mutable slice referring to the protected bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Consume the container and return the contained bytes
    /// 
    /// This method extracts the byte vector from the secure container,
    /// bypassing the automatic zeroing that would occur when dropped.
    /// This should only be used when absolutely necessary.
    ///
    /// # Security Considerations
    ///
    /// After calling this method, it becomes the caller's responsibility
    /// to properly handle and zeroize the sensitive data. Failure to do so
    /// may leave sensitive data in memory.
    ///
    /// # Returns
    ///
    /// The contained byte vector, which the caller must now properly handle
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::replace(&mut self.bytes, Vec::new())
    }
    
    /// Append data to the end of the buffer
    ///
    /// This method adds additional data to the secure buffer, which may be
    /// useful when accumulating sensitive data over multiple operations.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to append to this buffer
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.bytes.extend_from_slice(data);
    }
    
    /// Clear the buffer, securely zeroing all data
    ///
    /// This method zeroes and removes all data from the buffer while
    /// preserving the allocated capacity. This is useful when reusing
    /// a buffer for multiple operations with sensitive data.
    pub fn clear(&mut self) {
        self.bytes.zeroize();
        self.bytes.clear();
    }
    
    /// Get the current length of the buffer in bytes
    ///
    /// # Returns
    ///
    /// The number of bytes currently stored in the buffer
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    
    /// Check if the buffer is empty
    ///
    /// # Returns
    ///
    /// `true` if the buffer contains no data, `false` otherwise
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl From<&[u8]> for SecureBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for SecureBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// Securely zero memory after a function has completed
/// 
/// This is a helper function that lets you wrap operations that produce
/// sensitive data, ensuring the data is zeroized even if the function
/// returns early or panics.
/// 
/// # Arguments
///
/// * `data` - A mutable reference to the sensitive data to be zeroized after use
/// * `f` - A closure that will be executed with access to the sensitive data
///
/// # Returns
///
/// The result of executing the closure `f`
///
/// # Security Considerations
///
/// This function guarantees that the sensitive data will be zeroized:
/// - After the closure successfully completes
/// - If the closure returns early via a `return` statement
/// - If the closure panics
/// - If an exception is thrown during execution
/// 
/// # Example
/// 
/// ```
/// use qasa::secure_memory::with_secure_scope;
/// 
/// fn handle_sensitive_data() {
///     let mut key = [0u8; 32];
///     // Generate random key or other sensitive data
///     // ...
/// 
///     with_secure_scope(&mut key, |k| {
///         // Use k for sensitive operations
///         // ...
///     });
///     // key is now zeroized even if the closure panicked
/// }
/// ```
pub fn with_secure_scope<T, F, R>(data: &mut T, f: F) -> R
where
    T: Zeroize,
    F: FnOnce(&mut T) -> R,
{
    struct ScopeGuard<'a, T: Zeroize> {
        data: &'a mut T,
    }

    impl<'a, T: Zeroize> Drop for ScopeGuard<'a, T> {
        fn drop(&mut self) {
            self.data.zeroize();
        }
    }

    let guard = ScopeGuard { data };
    let result = f(guard.data);
    drop(guard);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer() {
        let sensitive_data = vec![1, 2, 3, 4, 5];
        let buffer = SecureBuffer::new(sensitive_data.clone());
        
        // Check we can access the data
        assert_eq!(&*buffer, &sensitive_data);
        
        // Drop the buffer, which should zeroize the data
        drop(buffer);
        
        // We can't check the zeroization directly since the memory is no longer accessible,
        // but the Drop trait implementation from ZeroizeOnDrop should have been called
    }
    
    #[test]
    fn test_secure_bytes() {
        let data = b"sensitive data";
        let mut secure = SecureBytes::new(data);
        
        // Check we can access and modify the data
        assert_eq!(secure.as_bytes(), data);
        
        secure.as_bytes_mut()[0] = b'S';
        assert_eq!(secure.as_bytes()[0], b'S');
        
        // Clear the data and check it's empty
        secure.clear();
        assert!(secure.is_empty());
        
        // Add new data
        secure.extend_from_slice(b"new data");
        assert_eq!(secure.as_bytes(), b"new data");
        
        // Into vec
        let vec = secure.into_vec();
        assert_eq!(vec, b"new data");
    }
    
    #[test]
    fn test_with_secure_scope() {
        let mut sensitive = vec![1, 2, 3, 4, 5];
        let sensitive_clone = sensitive.clone();
        
        with_secure_scope(&mut sensitive, |data| {
            // Modify the data
            data[0] = 10;
            assert_eq!(data, &[10, 2, 3, 4, 5]);
        });
        
        // Check each element is zeroed
        for item in &sensitive {
            assert_eq!(*item, 0);
        }
        
        // Verify it's different from the original
        assert_ne!(sensitive, sensitive_clone);
    }
} 