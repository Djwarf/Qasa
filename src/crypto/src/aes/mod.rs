/*!
 * AES-GCM implementation for symmetric encryption
 *
 * This module implements AES-GCM for symmetric encryption operations
 * used alongside the post-quantum algorithms.
 */

mod aes;

pub use aes::*;

#[cfg(test)]
mod tests;
