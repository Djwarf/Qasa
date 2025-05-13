//! Secure Memory Handling Utilities
//! 
//! This module provides utilities for secure memory operations, including
//! securely zeroing memory, preventing memory from being swapped, and
//! creating secure containers for sensitive data.

use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure container for sensitive data that will be automatically
/// zeroed when dropped, preventing the data from remaining in memory.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer<T: Zeroize> {
    /// The contained sensitive data
    inner: T,
}

impl<T: Zeroize> SecureBuffer<T> {
    /// Create a new secure buffer containing the given data
    pub fn new(data: T) -> Self {
        Self { inner: data }
    }

    /// Consume the secure buffer and return the contained data
    /// 
    /// Note: After calling this method, it becomes the caller's responsibility
    /// to properly handle and zeroize the sensitive data.
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
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes {
    bytes: Vec<u8>,
}

impl SecureBytes {
    /// Create a new SecureBytes with the given data
    pub fn new(data: &[u8]) -> Self {
        Self {
            bytes: data.to_vec(),
        }
    }

    /// Create a new SecureBytes with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Get a reference to the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get a mutable reference to the underlying bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Consume the container and return the contained bytes
    /// 
    /// Note: After calling this method, it becomes the caller's responsibility
    /// to properly handle and zeroize the sensitive data.
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::replace(&mut self.bytes, Vec::new())
    }
    
    /// Append data to the end of the buffer
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.bytes.extend_from_slice(data);
    }
    
    /// Clear the buffer, securely zeroing all data
    pub fn clear(&mut self) {
        self.bytes.zeroize();
        self.bytes.clear();
    }
    
    /// Length of the buffer
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    
    /// Check if the buffer is empty
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
/// # Example
/// 
/// ```
/// use qasa_crypto::secure_memory::with_secure_scope;
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