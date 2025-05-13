/*!
 * CRYSTALS-Kyber implementation for quantum-resistant key encapsulation
 * 
 * This module implements the CRYSTALS-Kyber algorithm for key encapsulation
 * as standardized by NIST for post-quantum cryptography.
 */

mod impl_kyber;

pub use impl_kyber::*;

#[cfg(test)]
mod tests; 