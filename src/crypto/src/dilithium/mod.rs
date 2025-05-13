/*!
 * CRYSTALS-Dilithium implementation for quantum-resistant digital signatures
 * 
 * This module implements the CRYSTALS-Dilithium algorithm for digital signatures
 * as standardized by NIST for post-quantum cryptography.
 */

mod impl_dilithium;
mod optimizations;

pub use impl_dilithium::*;

#[cfg(test)]
mod tests; 