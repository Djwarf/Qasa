//! Polynomial arithmetic for BIKE in GF(2)[x]/(x^r - 1)
//!
//! This module implements polynomial operations over GF(2) (binary field)
//! for use in the BIKE cryptosystem.

use crate::error::{CryptoError, CryptoResult};

/// Represents a polynomial in GF(2)[x]/(x^r - 1)
/// Coefficients are stored as bits in a Vec<u8>
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryPolynomial {
    /// Coefficients stored as bits (little-endian bit ordering)
    /// Each byte stores 8 coefficients, LSB first
    coeffs: Vec<u8>,
    /// Degree of the reduction polynomial (r value)
    r: usize,
}

impl BinaryPolynomial {
    /// Create a new polynomial with given r value
    pub fn new(r: usize) -> Self {
        let num_bytes = (r + 7) / 8;
        Self {
            coeffs: vec![0u8; num_bytes],
            r,
        }
    }

    /// Create a polynomial from bytes
    pub fn from_bytes(bytes: &[u8], r: usize) -> CryptoResult<Self> {
        let num_bytes = (r + 7) / 8;
        if bytes.len() != num_bytes {
            return Err(CryptoError::bike_error(
                "polynomial_from_bytes",
                &format!("Invalid byte length: expected {}, got {}", num_bytes, bytes.len()),
                crate::error::error_codes::BIKE_INVALID_KEY_SIZE,
            ));
        }

        let mut poly = Self::new(r);
        poly.coeffs.copy_from_slice(bytes);

        // Clear any bits beyond r
        let extra_bits = (8 - (r % 8)) % 8;
        if extra_bits > 0 && !poly.coeffs.is_empty() {
            let last_idx = poly.coeffs.len() - 1;
            poly.coeffs[last_idx] &= (1u8 << (8 - extra_bits)) - 1;
        }

        Ok(poly)
    }

    /// Get coefficient at position i (returns 0 or 1)
    pub fn get_coeff(&self, i: usize) -> u8 {
        if i >= self.r {
            return 0;
        }
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        (self.coeffs[byte_idx] >> bit_idx) & 1
    }

    /// Set coefficient at position i
    pub fn set_coeff(&mut self, i: usize, val: u8) {
        if i >= self.r {
            return;
        }
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if val & 1 == 1 {
            self.coeffs[byte_idx] |= 1 << bit_idx;
        } else {
            self.coeffs[byte_idx] &= !(1 << bit_idx);
        }
    }

    /// Flip (XOR) coefficient at position i
    pub fn flip_coeff(&mut self, i: usize) {
        if i >= self.r {
            return;
        }
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        self.coeffs[byte_idx] ^= 1 << bit_idx;
    }

    /// Get Hamming weight (number of 1s)
    pub fn hamming_weight(&self) -> usize {
        self.coeffs.iter().map(|&b| b.count_ones() as usize).sum()
    }

    /// Add two polynomials (XOR in GF(2))
    pub fn add(&self, other: &Self) -> CryptoResult<Self> {
        if self.r != other.r {
            return Err(CryptoError::bike_error(
                "polynomial_add",
                "Cannot add polynomials with different r values",
                crate::error::error_codes::BIKE_DECAPSULATION_FAILED,
            ));
        }

        let mut result = Self::new(self.r);
        for i in 0..self.coeffs.len() {
            result.coeffs[i] = self.coeffs[i] ^ other.coeffs[i];
        }
        Ok(result)
    }

    /// Multiply two polynomials modulo x^r - 1
    pub fn mul(&self, other: &Self) -> CryptoResult<Self> {
        if self.r != other.r {
            return Err(CryptoError::bike_error(
                "polynomial_mul",
                "Cannot multiply polynomials with different r values",
                crate::error::error_codes::BIKE_DECAPSULATION_FAILED,
            ));
        }

        let mut result = Self::new(self.r);

        // For each coefficient in self
        for i in 0..self.r {
            if self.get_coeff(i) == 0 {
                continue;
            }
            // Multiply by x^i and add to result
            for j in 0..self.r {
                if other.get_coeff(j) == 1 {
                    // Add x^(i+j) mod (x^r - 1)
                    let pos = (i + j) % self.r;
                    result.flip_coeff(pos);
                }
            }
        }

        Ok(result)
    }

    /// Compute cyclic rotation by n positions
    pub fn rotate(&self, n: usize) -> Self {
        let mut result = Self::new(self.r);
        for i in 0..self.r {
            if self.get_coeff(i) == 1 {
                result.set_coeff((i + n) % self.r, 1);
            }
        }
        result
    }

    /// Get the bytes representation
    pub fn to_bytes(&self) -> Vec<u8> {
        self.coeffs.clone()
    }

    /// Get r value
    pub fn r(&self) -> usize {
        self.r
    }

    /// Create a polynomial with random coefficients of given weight
    pub fn random_with_weight(r: usize, weight: usize) -> CryptoResult<Self> {
        use rand::Rng;

        if weight > r {
            return Err(CryptoError::bike_error(
                "random_polynomial",
                "Weight cannot exceed r",
                crate::error::error_codes::BIKE_KEY_GENERATION_FAILED,
            ));
        }

        let mut poly = Self::new(r);
        let mut rng = rand::thread_rng();
        let mut positions = Vec::new();

        // Generate unique random positions
        while positions.len() < weight {
            let pos = rng.gen_range(0..r);
            if !positions.contains(&pos) {
                positions.push(pos);
                poly.set_coeff(pos, 1);
            }
        }

        Ok(poly)
    }

    /// Compute syndrome: s = h * e^T where h is this polynomial
    pub fn compute_syndrome(&self, error: &Self) -> CryptoResult<Self> {
        // Syndrome is the product of public key (h) and error vector
        self.mul(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_creation() {
        let poly = BinaryPolynomial::new(100);
        assert_eq!(poly.r(), 100);
        assert_eq!(poly.hamming_weight(), 0);
    }

    #[test]
    fn test_set_get_coeff() {
        let mut poly = BinaryPolynomial::new(100);
        poly.set_coeff(5, 1);
        poly.set_coeff(10, 1);
        poly.set_coeff(99, 1);

        assert_eq!(poly.get_coeff(5), 1);
        assert_eq!(poly.get_coeff(10), 1);
        assert_eq!(poly.get_coeff(99), 1);
        assert_eq!(poly.get_coeff(0), 0);
        assert_eq!(poly.get_coeff(50), 0);
    }

    #[test]
    fn test_hamming_weight() {
        let mut poly = BinaryPolynomial::new(100);
        assert_eq!(poly.hamming_weight(), 0);

        poly.set_coeff(1, 1);
        poly.set_coeff(5, 1);
        poly.set_coeff(10, 1);
        assert_eq!(poly.hamming_weight(), 3);
    }

    #[test]
    fn test_add() {
        let mut poly1 = BinaryPolynomial::new(100);
        let mut poly2 = BinaryPolynomial::new(100);

        poly1.set_coeff(1, 1);
        poly1.set_coeff(5, 1);

        poly2.set_coeff(5, 1);
        poly2.set_coeff(10, 1);

        let result = poly1.add(&poly2).unwrap();
        assert_eq!(result.get_coeff(1), 1);
        assert_eq!(result.get_coeff(5), 0); // 1 XOR 1 = 0
        assert_eq!(result.get_coeff(10), 1);
    }

    #[test]
    fn test_mul() {
        let mut poly1 = BinaryPolynomial::new(10);
        let mut poly2 = BinaryPolynomial::new(10);

        // poly1 = x^2 + 1
        poly1.set_coeff(0, 1);
        poly1.set_coeff(2, 1);

        // poly2 = x + 1
        poly2.set_coeff(0, 1);
        poly2.set_coeff(1, 1);

        // (x^2 + 1)(x + 1) = x^3 + x^2 + x + 1
        let result = poly1.mul(&poly2).unwrap();
        assert_eq!(result.get_coeff(0), 1);
        assert_eq!(result.get_coeff(1), 1);
        assert_eq!(result.get_coeff(2), 1);
        assert_eq!(result.get_coeff(3), 1);
    }

    #[test]
    fn test_rotate() {
        let mut poly = BinaryPolynomial::new(10);
        poly.set_coeff(0, 1);
        poly.set_coeff(2, 1);

        let rotated = poly.rotate(3);
        assert_eq!(rotated.get_coeff(3), 1);
        assert_eq!(rotated.get_coeff(5), 1);
        assert_eq!(rotated.get_coeff(0), 0);
    }
}
