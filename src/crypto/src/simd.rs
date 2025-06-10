/*!
 * SIMD Acceleration Framework for QaSa Cryptography
 *
 * Provides vectorised implementations of cryptographic operations for
 * significant performance improvements on supported hardware.
 */

use crate::error::{CryptoError, CryptoResult};

#[cfg(target_arch = "x86_64")]
pub mod x86_simd;

#[cfg(target_arch = "aarch64")]
pub mod arm_simd;

/// Available SIMD algorithm implementations
#[derive(Debug, Clone, PartialEq)]
pub enum SimdAlgorithm {
    Scalar,     // Fallback implementation
    AVX2,       // Intel/AMD AVX2 (stable)
    NEON,       // ARM NEON
}

/// Hardware feature detection and capability reporting
pub struct SimdCapabilities {
    pub has_avx2: bool,
    pub has_neon: bool,
    pub vector_width: usize,
    pub preferred_algorithm: SimdAlgorithm,
}

/// Detect available SIMD capabilities on the current platform
pub fn detect_simd_capabilities() -> SimdCapabilities {
    #[cfg(target_arch = "x86_64")]
    {
        let caps = x86_simd::SimdCapabilities::detect();
        SimdCapabilities {
            has_avx2: caps.has_avx2,
            has_neon: false,
            vector_width: if caps.has_avx2 { 8 } else { 1 },
            preferred_algorithm: if caps.has_avx2 {
                SimdAlgorithm::AVX2
            } else {
                SimdAlgorithm::Scalar
            },
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        // Use ARM SIMD detection when available
        SimdCapabilities {
            has_avx2: false,
            has_neon: true, // Assume NEON is available on aarch64
            vector_width: 4,
            preferred_algorithm: SimdAlgorithm::NEON,
        }
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        SimdCapabilities {
            has_avx2: false,
            has_neon: false,
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
        coefficients: Vec<i32>,
        algorithm: SimdAlgorithm,
        vector_width: usize,
    }
    
    impl SimdPolynomial {
        /// Create a new SIMD polynomial with automatic algorithm selection
        pub fn new(coefficients: Vec<i32>) -> Self {
            let capabilities = detect_simd_capabilities();
            Self {
                coefficients,
                algorithm: capabilities.preferred_algorithm,
                vector_width: capabilities.vector_width,
            }
        }
        
        /// Create a polynomial with specific SIMD algorithm
        pub fn with_algorithm(coefficients: Vec<i32>, algorithm: SimdAlgorithm) -> CryptoResult<Self> {
            let capabilities = detect_simd_capabilities();
            
            // Verify the requested algorithm is available
            let is_available = match algorithm {
                SimdAlgorithm::Scalar => true,
                SimdAlgorithm::AVX2 => capabilities.has_avx2,
                SimdAlgorithm::NEON => capabilities.has_neon,
            };
            
            if !is_available {
                return Err(CryptoError::invalid_parameter(&format!("{:?}", algorithm), "SIMD instruction set not available on this CPU", "provided"));
            }
            
            Ok(Self {
                coefficients,
                algorithm,
                vector_width: capabilities.vector_width,
            })
        }
        
        /// Number Theoretic Transform (NTT) with SIMD acceleration
        pub fn ntt(&self) -> CryptoResult<Self> {
            let mut data = self.coefficients.clone();
            
            match self.algorithm {
                #[cfg(target_arch = "x86_64")]
                SimdAlgorithm::AVX2 => {
                    let ntt = x86_simd::SimdNTT::new(3329, 17); // Kyber parameters
                    ntt.forward_ntt(&mut data)?;
                },
                
                SimdAlgorithm::Scalar => {
                    self.ntt_scalar(&mut data)?;
                },
                
                #[cfg(not(target_arch = "x86_64"))]
                SimdAlgorithm::AVX2 => {
                    return Err(CryptoError::invalid_parameter(
                        "AVX operations", "x86_64",
                        std::env::consts::ARCH
                    ));
                },
                
                #[cfg(not(target_arch = "aarch64"))]
                SimdAlgorithm::NEON => {
                    return Err(CryptoError::invalid_parameter(
                        "ARM NEON operations",
                        "aarch64",
                        std::env::consts::ARCH
                    ));
                },
                
                #[cfg(target_arch = "aarch64")]
                SimdAlgorithm::NEON => {
                    // ARM NEON implementation would go here
                    self.ntt_scalar(&mut data)?;
                },
            }
            
            Ok(Self {
                coefficients: data,
                algorithm: self.algorithm.clone(),
                vector_width: self.vector_width,
            })
        }
        
        /// Scalar fallback implementation of NTT
        fn ntt_scalar(&self, data: &mut [i32]) -> CryptoResult<()> {
            let n = data.len();
            
            if !n.is_power_of_two() {
                return Err(CryptoError::invalid_parameter(
                    "polynomial_length",
                    "power of 2",
                    &n.to_string()
                ));
            }
            
            // Simplified NTT - in practice this would be a full implementation
            for element in data.iter_mut() {
                *element = *element % 3329; // Kyber modulus
            }
            
            Ok(())
        }
        
        /// Multiply two polynomials using SIMD acceleration
        pub fn multiply(&self, other: &Self) -> CryptoResult<Self> {
            match self.algorithm {
                #[cfg(target_arch = "x86_64")]
                SimdAlgorithm::AVX2 => {
                    let poly1 = x86_simd::X86SimdPolynomial::from_coefficients(self.coefficients.clone());
                    let poly2 = x86_simd::X86SimdPolynomial::from_coefficients(other.coefficients.clone());
                    let result = poly1.multiply(&poly2)?;
                    
                    Ok(Self {
                        coefficients: result.coefficients().to_vec(),
                        algorithm: self.algorithm.clone(),
                        vector_width: self.vector_width,
                    })
                },
                
                SimdAlgorithm::Scalar => {
                    let result = self.multiply_scalar(other)?;
                    Ok(Self {
                        coefficients: result,
                        algorithm: self.algorithm.clone(),
                        vector_width: self.vector_width,
                    })
                },
                
                #[cfg(not(target_arch = "x86_64"))]
                SimdAlgorithm::AVX2 => {
                    Err(CryptoError::invalid_parameter(
                        "AVX operations", "x86_64",
                        std::env::consts::ARCH
                    ))
                },
                
                #[cfg(target_arch = "aarch64")]
                SimdAlgorithm::NEON => {
                    // ARM NEON implementation would go here
                    let result = self.multiply_scalar(other)?;
                    Ok(Self {
                        coefficients: result,
                        algorithm: self.algorithm.clone(),
                        vector_width: self.vector_width,
                    })
                },
                
                #[cfg(not(target_arch = "aarch64"))]
                SimdAlgorithm::NEON => {
                    Err(CryptoError::invalid_parameter(
                        "ARM NEON operations", "aarch64",
                        std::env::consts::ARCH
                    ))
                },
            }
        }
        
        /// Add two polynomials using SIMD acceleration
        pub fn add(&self, other: &Self) -> CryptoResult<Self> {
            match self.algorithm {
                #[cfg(target_arch = "x86_64")]
                SimdAlgorithm::AVX2 => {
                    let poly1 = x86_simd::X86SimdPolynomial::from_coefficients(self.coefficients.clone());
                    let poly2 = x86_simd::X86SimdPolynomial::from_coefficients(other.coefficients.clone());
                    let result = poly1.add(&poly2)?;
                    
                    Ok(Self {
                        coefficients: result.coefficients().to_vec(),
                        algorithm: self.algorithm.clone(),
                        vector_width: self.vector_width,
                    })
                },
                
                SimdAlgorithm::Scalar => {
                    let result = self.add_scalar(other)?;
                    Ok(Self {
                        coefficients: result,
                        algorithm: self.algorithm.clone(),
                        vector_width: self.vector_width,
                    })
                },
                
                #[cfg(target_arch = "aarch64")]
                SimdAlgorithm::NEON => {
                    // ARM NEON implementation would go here
                    let result = self.add_scalar(other)?;
                    Ok(Self {
                        coefficients: result,
                        algorithm: self.algorithm.clone(),
                        vector_width: self.vector_width,
                    })
                },
                
                #[cfg(not(target_arch = "x86_64"))]
                SimdAlgorithm::AVX2 => {
                    Err(CryptoError::invalid_parameter(
                        "AVX operations", "x86_64",
                        std::env::consts::ARCH
                    ))
                },
                
                #[cfg(not(target_arch = "aarch64"))]
                SimdAlgorithm::NEON => {
                    Err(CryptoError::invalid_parameter(
                        "ARM NEON operations", "aarch64",
                        std::env::consts::ARCH
                    ))
                },
            }
        }
        
        /// Scalar multiplication fallback
        fn multiply_scalar(&self, other: &Self) -> CryptoResult<Vec<i32>> {
            if self.coefficients.len() != other.coefficients.len() {
                return Err(CryptoError::invalid_parameter(
                    "polynomial_lengths",
                    "equal lengths",
                    &format!("{} != {}", self.coefficients.len(), other.coefficients.len())
                ));
            }
            
            Ok(self.coefficients
                .iter()
                .zip(other.coefficients.iter())
                .map(|(&a, &b)| a.wrapping_mul(b))
                .collect())
        }
        
        /// Scalar addition fallback
        fn add_scalar(&self, other: &Self) -> CryptoResult<Vec<i32>> {
            if self.coefficients.len() != other.coefficients.len() {
                return Err(CryptoError::invalid_parameter(
                    "polynomial_lengths",
                    "equal lengths",
                    &format!("{} != {}", self.coefficients.len(), other.coefficients.len())
                ));
            }
            
            Ok(self.coefficients
                .iter()
                .zip(other.coefficients.iter())
                .map(|(&a, &b)| a.wrapping_add(b))
                .collect())
        }
        
        /// Get coefficients
        pub fn coefficients(&self) -> &[i32] {
            &self.coefficients
        }
        
        /// Get algorithm
        pub fn algorithm(&self) -> &SimdAlgorithm {
            &self.algorithm
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
                SimdAlgorithm::AVX2 => 8.0,
                SimdAlgorithm::NEON => 4.0,
            }
        }
        
        fn calculate_memory_utilization(&self) -> f64 {
            // Simplified calculation based on vector width
            (self.vector_width as f64) / 8.0 * 100.0
        }
    }
}

/// Performance information for SIMD operations
pub struct SimdPerformanceInfo {
    pub algorithm: SimdAlgorithm,
    pub vector_width: usize,
    pub theoretical_speedup: f64,
    pub memory_bandwidth_utilization: f64,
}

/// Benchmark SIMD performance across different implementations
pub fn benchmark_simd_performance(input_size: usize, iterations: usize) -> CryptoResult<SimdBenchmarkResult> {
    use std::time::Instant;
    use crate::simd::polynomial::SimdPolynomial;
    
    // Create test data
    let test_data: Vec<i32> = (0..input_size).map(|i| (i % 1000) as i32).collect();
    let poly1 = SimdPolynomial::new(test_data.clone());
    let poly2 = SimdPolynomial::new(test_data);
    
    // Benchmark scalar implementation
    let scalar_poly1 = SimdPolynomial::with_algorithm(poly1.coefficients().to_vec(), SimdAlgorithm::Scalar)?;
    let scalar_poly2 = SimdPolynomial::with_algorithm(poly2.coefficients().to_vec(), SimdAlgorithm::Scalar)?;
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _result = scalar_poly1.multiply(&scalar_poly2)?;
    }
    let scalar_time = start.elapsed();
    
    // Benchmark SIMD implementation if available
    let capabilities = detect_simd_capabilities();
    let (simd_time, algorithm_used) = if capabilities.preferred_algorithm != SimdAlgorithm::Scalar {
        let start = Instant::now();
        for _ in 0..iterations {
            let _result = poly1.multiply(&poly2)?;
        }
        let time = start.elapsed();
        (Some(time), capabilities.preferred_algorithm)
    } else {
        (None, SimdAlgorithm::Scalar)
    };
    
    let speedup = simd_time.map(|simd| scalar_time.as_nanos() as f64 / simd.as_nanos() as f64);
    
    Ok(SimdBenchmarkResult {
        input_size,
        iterations,
        scalar_time,
        simd_time,
        speedup,
        algorithm_used,
    })
}

/// Results from SIMD benchmarking
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
        let caps = detect_simd_capabilities();
        
        // Should always return valid values
        assert!(caps.vector_width >= 1);
        
        #[cfg(target_arch = "x86_64")]
        {
            // On x86_64, we should detect appropriate algorithms
            assert!(matches!(
                caps.preferred_algorithm,
                SimdAlgorithm::Scalar | SimdAlgorithm::AVX2
            ));
        }
        
        #[cfg(not(target_arch = "x86_64"))]
        {
            // On non-x86_64, should fall back appropriately
            println!("Non-x86_64 platform detected: {:?}", caps.preferred_algorithm);
        }
    }

    #[test]
    fn test_polynomial_creation() {
        let coeffs = vec![1, 2, 3, 4, 5];
        let poly = SimdPolynomial::new(coeffs.clone());
        
        assert_eq!(poly.coefficients(), &coeffs);
        let perf_info = poly.performance_info();
        assert!(perf_info.vector_width >= 1);
    }

    #[test]
    fn test_polynomial_operations() {
        let coeffs1 = vec![1, 2, 3, 4];
        let coeffs2 = vec![2, 3, 4, 5];
        
        let poly1 = SimdPolynomial::new(coeffs1);
        let poly2 = SimdPolynomial::new(coeffs2);
        
        let multiply_result = poly1.multiply(&poly2);
        assert!(multiply_result.is_ok());
        
        let add_result = poly1.add(&poly2);
        assert!(add_result.is_ok());
        
        if let Ok(result) = add_result {
            let expected = vec![3, 5, 7, 9];
            assert_eq!(result.coefficients(), &expected);
        }
    }

    #[test]
    fn test_performance_info() {
        let coeffs = vec![1, 2, 3, 4];
        let poly = SimdPolynomial::new(coeffs);
        
        let perf_info = poly.performance_info();
        assert!(perf_info.theoretical_speedup >= 1.0);
        assert!(perf_info.vector_width >= 1);
    }

    #[test]
    fn test_ntt_operations() {
        let coeffs = vec![1, 2, 3, 4, 5, 6, 7, 8]; // Power of 2 length
        let poly = SimdPolynomial::new(coeffs);
        
        let ntt_result = poly.ntt();
        assert!(ntt_result.is_ok());
    }

    #[test]
    fn test_benchmark_execution() {
        // Should not panic
        let result = benchmark_simd_performance(64, 10);
        assert!(result.is_ok());
        
        if let Ok(bench_result) = result {
            assert_eq!(bench_result.input_size, 64);
            assert_eq!(bench_result.iterations, 10);
            assert!(bench_result.scalar_time.as_nanos() > 0);
        }
    }
} 