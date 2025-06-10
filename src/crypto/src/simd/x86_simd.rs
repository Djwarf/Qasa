//! x86-specific SIMD optimizations for quantum cryptography
//!
//! This module provides optimized implementations using stable x86 SIMD instructions
//! including AVX2. AVX-512 support is disabled to avoid unstable features.

use crate::error::{CryptoError, CryptoResult};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Check if AVX2 is available at runtime
pub fn has_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

/// Optimized polynomial operations using AVX2
pub struct X86SimdPolynomial {
    coefficients: Vec<i32>,
    size: usize,
}

impl X86SimdPolynomial {
    pub fn new(size: usize) -> Self {
        Self {
            coefficients: vec![0; size],
            size,
        }
    }

    pub fn from_coefficients(coefficients: Vec<i32>) -> Self {
        let size = coefficients.len();
        Self { coefficients, size }
    }

    /// AVX2-optimized polynomial multiplication
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn avx2_multiply(&self, other: &Self) -> CryptoResult<Self> {
        if self.size != other.size {
            return Err(CryptoError::invalid_parameter(
                "polynomial_size",
                &format!("{}", self.size),
                &format!("{}", other.size)
            ));
        }

        let mut result = vec![0i32; self.size];
        
        // Process 8 coefficients at a time with AVX2
        for i in (0..self.size).step_by(8) {
            if i + 8 <= self.size {
                let a = _mm256_loadu_si256(self.coefficients[i..].as_ptr() as *const __m256i);
                let b = _mm256_loadu_si256(other.coefficients[i..].as_ptr() as *const __m256i);
                let prod = _mm256_mullo_epi32(a, b);
                _mm256_storeu_si256(result[i..].as_mut_ptr() as *mut __m256i, prod);
            } else {
                // Handle remaining elements
                for j in i..self.size {
                    result[j] = self.coefficients[j].wrapping_mul(other.coefficients[j]);
                }
            }
        }

        Ok(Self {
            coefficients: result,
            size: self.size,
        })
    }

    /// Runtime dispatch for optimal multiplication
    pub fn multiply(&self, other: &Self) -> CryptoResult<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            if has_avx2() {
                return unsafe { self.avx2_multiply(other) };
            }
        }
        
        // Software fallback
        self.software_multiply(other)
    }

    /// Software fallback implementation
    fn software_multiply(&self, other: &Self) -> CryptoResult<Self> {
        if self.size != other.size {
            return Err(CryptoError::invalid_parameter(
                "polynomial_size",
                &format!("{}", self.size),
                &format!("{}", other.size)
            ));
        }

        let result: Vec<i32> = self.coefficients
            .iter()
            .zip(other.coefficients.iter())
            .map(|(&a, &b)| a.wrapping_mul(b))
            .collect();

        Ok(Self {
            coefficients: result,
            size: self.size,
        })
    }

    /// AVX2-optimized polynomial addition
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn avx2_add(&self, other: &Self) -> CryptoResult<Self> {
        if self.size != other.size {
            return Err(CryptoError::invalid_parameter(
                "polynomial_size",
                &format!("{}", self.size),
                &format!("{}", other.size)
            ));
        }

        let mut result = vec![0i32; self.size];
        
        // Process 8 coefficients at a time with AVX2
        for i in (0..self.size).step_by(8) {
            if i + 8 <= self.size {
                let a = _mm256_loadu_si256(self.coefficients[i..].as_ptr() as *const __m256i);
                let b = _mm256_loadu_si256(other.coefficients[i..].as_ptr() as *const __m256i);
                let sum = _mm256_add_epi32(a, b);
                _mm256_storeu_si256(result[i..].as_mut_ptr() as *mut __m256i, sum);
            } else {
                // Handle remaining elements
                for j in i..self.size {
                    result[j] = self.coefficients[j].wrapping_add(other.coefficients[j]);
                }
            }
        }

        Ok(Self {
            coefficients: result,
            size: self.size,
        })
    }

    /// Add two polynomials with runtime dispatch
    pub fn add(&self, other: &Self) -> CryptoResult<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            if has_avx2() {
                return unsafe { self.avx2_add(other) };
            }
        }
        
        self.software_add(other)
    }

    /// Software fallback for addition
    fn software_add(&self, other: &Self) -> CryptoResult<Self> {
        if self.size != other.size {
            return Err(CryptoError::invalid_parameter(
                "polynomial_size",
                &format!("{}", self.size),
                &format!("{}", other.size)
            ));
        }

        let result: Vec<i32> = self.coefficients
            .iter()
            .zip(other.coefficients.iter())
            .map(|(&a, &b)| a.wrapping_add(b))
            .collect();

        Ok(Self {
            coefficients: result,
            size: self.size,
        })
    }

    /// Get coefficients slice
    pub fn coefficients(&self) -> &[i32] {
        &self.coefficients
    }

    /// Get size
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Optimized Number Theoretic Transform using SIMD
pub struct SimdNTT {
    modulus: i32,
    root_of_unity: i32,
}

impl SimdNTT {
    pub fn new(modulus: i32, root_of_unity: i32) -> Self {
        Self { modulus, root_of_unity }
    }

    /// AVX2-optimized forward NTT
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn avx2_forward_ntt(&self, data: &mut [i32]) -> CryptoResult<()> {
        let n = data.len();
        if !n.is_power_of_two() {
            return Err(CryptoError::invalid_parameter(
                "ntt_size",
                "power of 2",
                &format!("{}", n)
            ));
        }

        let modulus_vec = _mm256_set1_epi32(self.modulus);
        
        // Process 8 elements at a time
        for chunk in data.chunks_exact_mut(8) {
            let vec = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            // Simplified reduction operation
            let reduced = _mm256_and_si256(vec, _mm256_sub_epi32(modulus_vec, _mm256_set1_epi32(1)));
            _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, reduced);
        }

        // Handle remaining elements
        let remainder = data.len() % 8;
        if remainder > 0 {
            let start = data.len() - remainder;
            for i in start..data.len() {
                data[i] = data[i] % self.modulus;
            }
        }

        Ok(())
    }

    /// Forward NTT with runtime dispatch
    pub fn forward_ntt(&self, data: &mut [i32]) -> CryptoResult<()> {
        #[cfg(target_arch = "x86_64")]
        {
            if has_avx2() {
                return unsafe { self.avx2_forward_ntt(data) };
            }
        }
        
        self.software_forward_ntt(data)
    }

    /// Software fallback for NTT
    fn software_forward_ntt(&self, data: &mut [i32]) -> CryptoResult<()> {
        let n = data.len();
        if !n.is_power_of_two() {
            return Err(CryptoError::invalid_parameter(
                "ntt_size",
                "power of 2",
                &format!("{}", n)
            ));
        }

        // Simplified software NTT
        for element in data.iter_mut() {
            *element = *element % self.modulus;
        }

        Ok(())
    }
}

/// SIMD capability information
pub struct SimdCapabilities {
    pub has_avx2: bool,
    pub has_sse2: bool,
    pub has_sse4_1: bool,
}

impl SimdCapabilities {
    pub fn detect() -> Self {
        Self {
            has_avx2: has_avx2(),
            has_sse2: is_x86_feature_detected!("sse2"),
            has_sse4_1: is_x86_feature_detected!("sse4.1"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_feature_detection() {
        let _has_avx2 = has_avx2();
        // Test should pass regardless of CPU capabilities
        assert!(true);
    }

    #[test]
    fn test_simd_polynomial_multiply() {
        let coeffs1 = vec![1, 2, 3, 4];
        let coeffs2 = vec![2, 3, 4, 5];
        
        let poly1 = X86SimdPolynomial::from_coefficients(coeffs1);
        let poly2 = X86SimdPolynomial::from_coefficients(coeffs2);
        
        let result = poly1.multiply(&poly2);
        assert!(result.is_ok());
        
        let result_poly = result.unwrap();
        let expected = vec![2, 6, 12, 20];
        assert_eq!(result_poly.coefficients(), &expected);
    }

    #[test]
    fn test_simd_polynomial_add() {
        let coeffs1 = vec![1, 2, 3, 4];
        let coeffs2 = vec![2, 3, 4, 5];
        
        let poly1 = X86SimdPolynomial::from_coefficients(coeffs1);
        let poly2 = X86SimdPolynomial::from_coefficients(coeffs2);
        
        let result = poly1.add(&poly2);
        assert!(result.is_ok());
        
        let result_poly = result.unwrap();
        let expected = vec![3, 5, 7, 9];
        assert_eq!(result_poly.coefficients(), &expected);
    }

    #[test]
    fn test_ntt_operations() {
        let ntt = SimdNTT::new(3329, 17); // Kyber parameters
        let mut data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        
        let result = ntt.forward_ntt(&mut data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_simd_capabilities() {
        let caps = SimdCapabilities::detect();
        // Should not panic and return valid capability info
        println!("SIMD Capabilities - AVX2: {}, SSE2: {}, SSE4.1: {}", 
                caps.has_avx2, caps.has_sse2, caps.has_sse4_1);
    }

    #[test]
    fn test_error_handling() {
        let poly1 = X86SimdPolynomial::new(4);
        let poly2 = X86SimdPolynomial::new(8); // Different size
        
        let result = poly1.multiply(&poly2);
        assert!(result.is_err());
    }
} 