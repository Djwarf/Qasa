/*!
 * CRYSTALS-Dilithium implementation for quantum-resistant digital signatures
 *
 * This module implements the CRYSTALS-Dilithium algorithm for digital signatures
 * as standardized by NIST for post-quantum cryptography.
 */

mod dilithium;
mod optimizations;

pub use dilithium::*;
pub use optimizations::LeanDilithium;

#[cfg(test)]
mod tests;
