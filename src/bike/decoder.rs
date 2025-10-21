//! BGF (Bit Flipping Galois) Decoder for BIKE
//!
//! This module implements the iterative bit-flipping decoder used in BIKE
//! for error correction during decapsulation.

use super::polynomial::BinaryPolynomial;
use crate::error::{CryptoError, CryptoResult};

/// BGF decoder parameters
pub struct BgfDecoderParams {
    /// Block size (r)
    pub r: usize,
    /// Weight of error vector
    pub w: usize,
    /// Error correction capability
    pub t: usize,
    /// Number of iterations
    pub max_iterations: usize,
    /// Threshold for bit flipping
    pub threshold: usize,
}

impl BgfDecoderParams {
    /// Create parameters for BIKE Level 1
    pub fn level1() -> Self {
        Self {
            r: 12323,
            w: 142,
            t: 134,
            max_iterations: 100,
            threshold: 13,
        }
    }

    /// Create parameters for BIKE Level 3
    pub fn level3() -> Self {
        Self {
            r: 24659,
            w: 206,
            t: 199,
            max_iterations: 100,
            threshold: 20,
        }
    }

    /// Create parameters for BIKE Level 5
    pub fn level5() -> Self {
        Self {
            r: 40973,
            w: 274,
            t: 264,
            max_iterations: 100,
            threshold: 27,
        }
    }
}

/// BGF Decoder implementation
pub struct BgfDecoder {
    params: BgfDecoderParams,
}

impl BgfDecoder {
    /// Create a new BGF decoder with given parameters
    pub fn new(params: BgfDecoderParams) -> Self {
        Self { params }
    }

    /// Decode syndrome to recover error vector
    ///
    /// This implements the iterative bit-flipping algorithm:
    /// 1. Compute unsatisfied parity checks for each bit
    /// 2. Flip bits that have high number of unsatisfied checks
    /// 3. Repeat until syndrome is zero or max iterations reached
    pub fn decode(
        &self,
        syndrome: &BinaryPolynomial,
        h0: &BinaryPolynomial,
        h1: &BinaryPolynomial,
    ) -> CryptoResult<(BinaryPolynomial, BinaryPolynomial)> {
        // Initialize error estimates
        let mut e0 = BinaryPolynomial::new(self.params.r);
        let mut e1 = BinaryPolynomial::new(self.params.r);

        // Current syndrome
        let mut current_syndrome = syndrome.clone();

        for iteration in 0..self.params.max_iterations {
            // Check if decoding is complete (syndrome is zero)
            if current_syndrome.hamming_weight() == 0 {
                return Ok((e0, e1));
            }

            // Compute unsatisfied parity checks (UPC) for each position
            let mut upc0 = vec![0usize; self.params.r];
            let mut upc1 = vec![0usize; self.params.r];

            // For each position, count unsatisfied checks
            for i in 0..self.params.r {
                // Count unsatisfied checks for e0
                for j in 0..self.params.r {
                    if h0.get_coeff(j) == 1 && current_syndrome.get_coeff((i + j) % self.params.r) == 1 {
                        upc0[i] += 1;
                    }
                }

                // Count unsatisfied checks for e1
                for j in 0..self.params.r {
                    if h1.get_coeff(j) == 1 && current_syndrome.get_coeff((i + j) % self.params.r) == 1 {
                        upc1[i] += 1;
                    }
                }
            }

            // Determine threshold for this iteration
            let threshold = self.compute_threshold(iteration);

            // Flip bits with UPC above threshold
            let mut flipped = false;
            for i in 0..self.params.r {
                if upc0[i] >= threshold {
                    e0.flip_coeff(i);
                    flipped = true;
                }
                if upc1[i] >= threshold {
                    e1.flip_coeff(i);
                    flipped = true;
                }
            }

            if !flipped {
                // No bits flipped, try lowering threshold
                continue;
            }

            // Recompute syndrome
            // s = h0 * e0 + h1 * e1
            let syndrome0 = h0.compute_syndrome(&e0)?;
            let syndrome1 = h1.compute_syndrome(&e1)?;
            current_syndrome = syndrome0.add(&syndrome1)?;
        }

        // Check if we successfully decoded
        if current_syndrome.hamming_weight() == 0 {
            Ok((e0, e1))
        } else {
            Err(CryptoError::bike_error(
                "bgf_decode",
                &format!(
                    "Failed to decode after {} iterations, remaining syndrome weight: {}",
                    self.params.max_iterations,
                    current_syndrome.hamming_weight()
                ),
                crate::error::error_codes::BIKE_DECAPSULATION_FAILED,
            ))
        }
    }

    /// Compute threshold for given iteration
    fn compute_threshold(&self, iteration: usize) -> usize {
        // Use adaptive threshold that decreases with iterations
        let base_threshold = self.params.threshold;

        if iteration < 10 {
            base_threshold
        } else if iteration < 30 {
            base_threshold.saturating_sub(1)
        } else if iteration < 60 {
            base_threshold.saturating_sub(2)
        } else {
            base_threshold.saturating_sub(3)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgf_decoder_creation() {
        let params = BgfDecoderParams::level1();
        let decoder = BgfDecoder::new(params);
        assert_eq!(decoder.params.r, 12323);
    }

    #[test]
    fn test_bgf_decode_zero_syndrome() {
        let params = BgfDecoderParams::level1();
        let decoder = BgfDecoder::new(params);

        let syndrome = BinaryPolynomial::new(params.r);
        let h0 = BinaryPolynomial::new(params.r);
        let h1 = BinaryPolynomial::new(params.r);

        let result = decoder.decode(&syndrome, &h0, &h1);
        assert!(result.is_ok());
        let (e0, e1) = result.unwrap();
        assert_eq!(e0.hamming_weight(), 0);
        assert_eq!(e1.hamming_weight(), 0);
    }
}
