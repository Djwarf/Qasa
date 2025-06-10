/*!
 * SIMD Acceleration Framework for QaSa Cryptography
 *
 * Provides vectorised implementations of cryptographic operations for
 * significant performance improvements on supported hardware.
 */

use crate::error::{CryptoError, CryptoResult, error_codes};

#[cfg(target_arch = "x86_64")]
pub mod x86_simd;

#[cfg(target_arch = "aarch64")]
pub mod arm_simd;

/// Trait for SIMD-accelerated operations
pub trait SimdAccelerated {
    /// Vectorised multiplication operation
    fn simd_multiply(&self, other: &Self) -> Self;
    
    /// Vectorised addition operation
    fn simd_add(&self, other: &Self) -> Self;
    
    /// Vectorised subtraction operation
    fn simd_subtract(&self, other: &Self) -> Self;
    
    /// Check if SIMD acceleration is available for this operation
    fn simd_available() -> bool;
    
    /// Get the optimal vector width for this operation
    fn optimal_vector_width() -> usize;
}

/// Hardware feature detection and capability reporting
pub struct SimdCapabilities {
    pub has_avx2: bool,
    pub has_avx512: bool,
    pub has_neon: bool,
    pub has_sve: bool,
    pub vector_width: usize,
    pub preferred_algorithm: SimdAlgorithm,
}

/// Available SIMD algorithm implementations
#[derive(Debug, Clone, PartialEq)]
pub enum SimdAlgorithm {
    Scalar,     // Fallback implementation
    AVX2,       // Intel/AMD AVX2
    AVX512,     // Intel/AMD AVX-512
    NEON,       // ARM NEON
    SVE,        // ARM SVE
}

/// Detect available SIMD capabilities on the current platform
pub fn detect_simd_capabilities() -> SimdCapabilities {
    #[cfg(target_arch = "x86_64")]
    {
        x86_simd::detect_x86_capabilities()
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        arm_simd::detect_arm_capabilities()
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        SimdCapabilities {
            has_avx2: false,
            has_avx512: false,
            has_neon: false,
            has_sve: false,
            vector_width: 1,
            preferred_algorithm: SimdAlgorithm::Scalar,
        }
    }
}

/// Vectorised polynomial operations for post-quantum cryptography
pub mod polynomial {
    use super::*;
    
    /// Represents a polynomial with SIMD acceleration support
    #[derive(Debug, Clone)]
    pub struct SimdPolynomial {
        coefficients: Vec<i16>,
        algorithm: SimdAlgorithm,
        vector_width: usize,
    }
    
    impl SimdPolynomial {
        /// Create a new SIMD polynomial with automatic algorithm selection
        pub fn new(coefficients: Vec<i16>) -> Self {
            let capabilities = detect_simd_capabilities();
            Self {
                coefficients,
                algorithm: capabilities.preferred_algorithm,
                vector_width: capabilities.vector_width,
            }
        }
        
        /// Create a polynomial with specific SIMD algorithm
        pub fn with_algorithm(coefficients: Vec<i16>, algorithm: SimdAlgorithm) -> CryptoResult<Self> {
            let capabilities = detect_simd_capabilities();
            
            // Verify the requested algorithm is available
            let is_available = match algorithm {
                SimdAlgorithm::Scalar => true,
                SimdAlgorithm::AVX2 => capabilities.has_avx2,
                SimdAlgorithm::AVX512 => capabilities.has_avx512,
                SimdAlgorithm::NEON => capabilities.has_neon,
                SimdAlgorithm::SVE => capabilities.has_sve,
            };
            
            if !is_available {
                return Err(CryptoError::HardwareAccelerationError {
                    operation: format!("{:?}", algorithm),
                    cause: "SIMD instruction set not available on this CPU".to_string(),
                    error_code: error_codes::SIMD_NOT_AVAILABLE,
                });
            }
            
            Ok(Self {
                coefficients,
                algorithm,
                vector_width: capabilities.vector_width,
            })
        }
        
        /// Number Theoretic Transform (NTT) with SIMD acceleration
        pub fn ntt(&self) -> CryptoResult<Self> {
            match self.algorithm {
                #[cfg(target_arch = "x86_64")]
                SimdAlgorithm::AVX2 => x86_simd::ntt_avx2(&self.coefficients),
                
                #[cfg(target_arch = "x86_64")]
                SimdAlgorithm::AVX512 => x86_simd::ntt_avx512(&self.coefficients),
                
                #[cfg(target_arch = "aarch64")]
                SimdAlgorithm::NEON => arm_simd::ntt_neon(&self.coefficients),
                
                #[cfg(target_arch = "aarch64")]
                SimdAlgorithm::SVE => arm_simd::ntt_sve(&self.coefficients),
                
                SimdAlgorithm::Scalar => self.ntt_scalar(),
                
                #[cfg(not(target_arch = "x86_64"))]
                SimdAlgorithm::AVX2 | SimdAlgorithm::AVX512 => {
                    Err(CryptoError::UnsupportedOperation {
                        operation: "AVX operations".to_string(),
                        platform: std::env::consts::ARCH.to_string(),
                        error_code: error_codes::SIMD_NOT_AVAILABLE,
                    })
                },
                
                #[cfg(not(target_arch = "aarch64"))]
                SimdAlgorithm::NEON | SimdAlgorithm::SVE => {
                    Err(CryptoError::UnsupportedOperation {
                        operation: "ARM SIMD operations".to_string(),
                        platform: std::env::consts::ARCH.to_string(),
                        error_code: error_codes::SIMD_NOT_AVAILABLE,
                    })
                },
            }
        }
        
        /// Scalar fallback implementation of NTT
        fn ntt_scalar(&self) -> CryptoResult<Self> {
            // Basic NTT implementation without SIMD
            let mut result = self.coefficients.clone();
            let n = result.len();
            
            if !n.is_power_of_two() {
                return Err(CryptoError::InvalidParameter {
                    parameter: "polynomial_length".to_string(),
                    expected: "power of 2".to_string(),
                    actual: n.to_string(),
                    error_code: 9999,
                });
            }
            
            // Simplified NTT - in practice this would be a full implementation
            for i in 0..n {
                for j in 0..n {
                    if i != j {
                        result[i] = result[i].wrapping_add(result[j]);
                    }
                }
            }
            
            Ok(Self {
                coefficients: result,
                algorithm: self.algorithm.clone(),
                vector_width: self.vector_width,
            })
        }
        
        /// Get performance statistics for the current algorithm
        pub fn performance_info(&self) -> SimdPerformanceInfo {
            SimdPerformanceInfo {
                algorithm: self.algorithm.clone(),
                vector_width: self.vector_width,
                theoretical_speedup: self.calculate_theoretical_speedup(),
                memory_bandwidth_utilization: self.calculate_memory_utilization(),
            }
        }
        
        fn calculate_theoretical_speedup(&self) -> f64 {
            match self.algorithm {
                SimdAlgorithm::Scalar => 1.0,
                SimdAlgorithm::AVX2 => 4.0,      // 256-bit / 64-bit
                SimdAlgorithm::AVX512 => 8.0,    // 512-bit / 64-bit
                SimdAlgorithm::NEON => 2.0,      // 128-bit / 64-bit
                SimdAlgorithm::SVE => 4.0,       // Variable width, assume 256-bit
            }
        }
        
        fn calculate_memory_utilization(&self) -> f64 {
            // Simplified calculation based on vector width
            (self.vector_width as f64) / 8.0 // Assume 8-wide baseline
        }
    }
    
    impl SimdAccelerated for SimdPolynomial {
        fn simd_multiply(&self, other: &Self) -> Self {
            // Dispatch to appropriate SIMD implementation
            match self.algorithm {
                #[cfg(target_arch = "x86_64")]
                SimdAlgorithm::AVX2 => {
                    let result = x86_simd::multiply_avx2(&self.coefficients, &other.coefficients)
                        .unwrap_or_else(|_| self.multiply_scalar(other));
                    SimdPolynomial::new(result)
                },
                
                #[cfg(target_arch = "aarch64")]
                SimdAlgorithm::NEON => {
                    let result = arm_simd::multiply_neon(&self.coefficients, &other.coefficients)
                        .unwrap_or_else(|_| self.multiply_scalar(other));
                    SimdPolynomial::new(result)
                },
                
                _ => SimdPolynomial::new(self.multiply_scalar(other)),
            }
        }
        
        fn simd_add(&self, other: &Self) -> Self {
            // Similar pattern for addition
            SimdPolynomial::new(self.add_scalar(other))
        }
        
        fn simd_subtract(&self, other: &Self) -> Self {
            // Similar pattern for subtraction
            SimdPolynomial::new(self.subtract_scalar(other))
        }
        
        fn simd_available() -> bool {
            !matches!(detect_simd_capabilities().preferred_algorithm, SimdAlgorithm::Scalar)
        }
        
        fn optimal_vector_width() -> usize {
            detect_simd_capabilities().vector_width
        }
    }
    
    impl SimdPolynomial {
        fn multiply_scalar(&self, other: &Self) -> Vec<i16> {
            let mut result = vec![0i16; self.coefficients.len()];
            for i in 0..self.coefficients.len() {
                result[i] = self.coefficients[i].wrapping_mul(
                    other.coefficients.get(i).copied().unwrap_or(0)
                );
            }
            result
        }
        
        fn add_scalar(&self, other: &Self) -> Vec<i16> {
            let mut result = vec![0i16; self.coefficients.len()];
            for i in 0..self.coefficients.len() {
                result[i] = self.coefficients[i].wrapping_add(
                    other.coefficients.get(i).copied().unwrap_or(0)
                );
            }
            result
        }
        
        fn subtract_scalar(&self, other: &Self) -> Vec<i16> {
            let mut result = vec![0i16; self.coefficients.len()];
            for i in 0..self.coefficients.len() {
                result[i] = self.coefficients[i].wrapping_sub(
                    other.coefficients.get(i).copied().unwrap_or(0)
                );
            }
            result
        }
    }
}

/// Performance information for SIMD operations
#[derive(Debug, Clone)]
pub struct SimdPerformanceInfo {
    pub algorithm: SimdAlgorithm,
    pub vector_width: usize,
    pub theoretical_speedup: f64,
    pub memory_bandwidth_utilization: f64,
}

/// Benchmark SIMD performance against scalar implementation
pub fn benchmark_simd_performance(input_size: usize, iterations: usize) -> CryptoResult<SimdBenchmarkResult> {
    use std::time::Instant;
    use crate::simd::polynomial::SimdPolynomial;
    
    // Generate test data
    let test_data: Vec<i16> = (0..input_size).map(|i| (i % 1000) as i16).collect();
    let poly_scalar = SimdPolynomial::with_algorithm(test_data.clone(), SimdAlgorithm::Scalar)?;
    
    // Benchmark scalar implementation
    let start = Instant::now();
    for _ in 0..iterations {
        let _result = poly_scalar.ntt()?;
    }
    let scalar_time = start.elapsed();
    
    // Benchmark SIMD implementation if available
    let capabilities = detect_simd_capabilities();
    let simd_time = if capabilities.preferred_algorithm != SimdAlgorithm::Scalar {
        let poly_simd = SimdPolynomial::with_algorithm(test_data, capabilities.preferred_algorithm.clone())?;
        
        let start = Instant::now();
        for _ in 0..iterations {
            let _result = poly_simd.ntt()?;
        }
        Some(start.elapsed())
    } else {
        None
    };
    
    Ok(SimdBenchmarkResult {
        input_size,
        iterations,
        scalar_time,
        simd_time,
        speedup: simd_time.map(|simd| scalar_time.as_secs_f64() / simd.as_secs_f64()),
        algorithm_used: capabilities.preferred_algorithm,
    })
}

/// Result of SIMD performance benchmarking
#[derive(Debug)]
pub struct SimdBenchmarkResult {
    pub input_size: usize,
    pub iterations: usize,
    pub scalar_time: std::time::Duration,
    pub simd_time: Option<std::time::Duration>,
    pub speedup: Option<f64>,
    pub algorithm_used: SimdAlgorithm,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simd::polynomial::SimdPolynomial;
    
    #[test]
    fn test_simd_capability_detection() {
        let capabilities = detect_simd_capabilities();
        
        // Should always have at least scalar support
        assert!(capabilities.vector_width >= 1);
        
        // Algorithm should be appropriate for the platform
        #[cfg(target_arch = "x86_64")]
        {
            assert!(matches!(
                capabilities.preferred_algorithm,
                SimdAlgorithm::Scalar | SimdAlgorithm::AVX2 | SimdAlgorithm::AVX512
            ));
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            assert!(matches!(
                capabilities.preferred_algorithm,
                SimdAlgorithm::Scalar | SimdAlgorithm::NEON | SimdAlgorithm::SVE
            ));
        }
    }
    
    #[test]
    fn test_polynomial_creation() {
        let coefficients = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let poly = SimdPolynomial::new(coefficients.clone());
        
        assert_eq!(poly.coefficients, coefficients);
        assert!(poly.vector_width >= 1);
    }
    
    #[test]
    fn test_scalar_polynomial_operations() {
        let coeffs_a = vec![1, 2, 3, 4];
        let coeffs_b = vec![2, 3, 4, 5];
        
        let poly_a = SimdPolynomial::with_algorithm(coeffs_a, SimdAlgorithm::Scalar).unwrap();
        let poly_b = SimdPolynomial::with_algorithm(coeffs_b, SimdAlgorithm::Scalar).unwrap();
        
        let result = poly_a.simd_add(&poly_b);
        assert_eq!(result.coefficients, vec![3, 5, 7, 9]);
        
        let result = poly_a.simd_multiply(&poly_b);
        assert_eq!(result.coefficients, vec![2, 6, 12, 20]);
    }
    
    #[test]
    fn test_performance_info() {
        let coefficients = vec![1; 256];
        let poly = SimdPolynomial::new(coefficients);
        let perf_info = poly.performance_info();
        
        assert!(perf_info.theoretical_speedup >= 1.0);
        assert!(perf_info.memory_bandwidth_utilization > 0.0);
    }
    
    #[test]
    fn test_simd_availability() {
        let available = SimdPolynomial::simd_available();
        let width = SimdPolynomial::optimal_vector_width();
        
        // These should always return valid values
        assert!(width >= 1);
        
        if available {
            assert!(width > 1);
        }
    }
} 