/*!
 * CRYSTALS-Dilithium implementation for quantum-resistant digital signatures
 *
 * This module implements the CRYSTALS-Dilithium algorithm for digital signatures
 * as standardized by NIST for post-quantum cryptography.
 */

mod dilithium;
mod optimizations;
mod compression;

pub use dilithium::*;
pub use optimizations::LeanDilithium;
pub use compression::{
    CompressedSignature,
    CompressionLevel,
    compress_signature,
    decompress_signature,
};

#[cfg(test)]
mod tests;
