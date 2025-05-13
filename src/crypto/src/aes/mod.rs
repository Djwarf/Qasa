/*!
 * AES-GCM implementation for symmetric encryption
 * 
 * This module implements AES-GCM for symmetric encryption operations
 * used alongside the post-quantum algorithms.
 */

mod impl_aes;

pub use impl_aes::*;

#[cfg(test)]
mod tests; 