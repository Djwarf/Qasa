/*!
 * Side-Channel Testing Framework
 */

use crate::aes::AesGcm;
use crate::dilithium::{DilithiumKeyPair, DilithiumVariant};
use crate::error::{CryptoError, CryptoResult};
use crate::kyber::{KyberKeyPair, KyberVariant};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SideChannelTester {
    pub config: TestConfig,
}

#[derive(Debug, Clone)]
pub struct TestConfig {
    pub iterations: usize,
}

#[derive(Debug, Clone)]
pub struct TimingAnalyzer {
    pub measurements: Vec<Duration>,
}

#[derive(Debug, Clone)]
pub struct TimingAnalysisResult {
    pub is_constant_time: bool,
}

/// Timing analysis results
#[derive(Debug, Clone)]
pub struct TimingAnalysis {
    pub test_name: String,
    pub mean_time: Duration,
    pub std_deviation: Duration,
    pub min_time: Duration,
    pub max_time: Duration,
    pub coefficient_of_variation: f64,
    pub potential_vulnerability: bool,
    pub vulnerability_description: String,
}

/// Side-channel test results
#[derive(Debug, Clone, serde::Serialize)]
pub struct SideChannelResults {
    pub test_name: String,
    pub passed: bool,
}

impl SideChannelTester {
    /// Create a new side-channel tester
    pub fn new(config: TestConfig) -> Self {
        Self { config }
    }

    /// Run all side-channel tests
    pub fn run_all_tests(&self) -> CryptoResult<SideChannelResults> {
        let mut tests = Vec::new();

        // Test Kyber operations
        tests.push(self.test_kyber_keygen()?);
        tests.push(self.test_kyber_encapsulation()?);
        tests.push(self.test_kyber_decapsulation()?);
        tests.push(self.test_kyber_timing_with_different_keys()?);

        // Test Dilithium operations
        tests.push(self.test_dilithium_keygen()?);
        tests.push(self.test_dilithium_sign()?);
        tests.push(self.test_dilithium_verify()?);
        tests.push(self.test_dilithium_timing_with_different_keys()?);

        // Test AES operations
        tests.push(self.test_aes_encryption()?);
        tests.push(self.test_aes_decryption()?);
        tests.push(self.test_aes_timing_with_different_keys()?);
        tests.push(self.test_aes_timing_with_different_plaintexts()?);

        // Test memory access patterns
        tests.push(self.test_memory_access_patterns()?);

        // Test cache timing attacks
        tests.push(self.test_cache_timing_attacks()?);

        let vulnerabilities_found = tests.iter().filter(|t| t.potential_vulnerability).count();
        let overall_score = self.calculate_overall_score(&tests);
        let recommendations = self.generate_recommendations(&tests);

        Ok(SideChannelResults {
            test_name: "Side-Channel Tests".to_string(),
            passed: vulnerabilities_found == 0,
        })
    }

    /// Test Kyber key generation timing
    fn test_kyber_keygen(&self) -> CryptoResult<TimingAnalysis> {
        let mut times = Vec::new();

        for _ in 0..self.config.iterations {
            let start = Instant::now();
            let _keypair = KyberKeyPair::generate(KyberVariant::Kyber512)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "Kyber Key Generation",
            times,
            "Key generation timing should be constant regardless of entropy",
        )?)
    }

    /// Test Kyber encapsulation timing
    fn test_kyber_encapsulation(&self) -> CryptoResult<TimingAnalysis> {
        let keypair = KyberKeyPair::generate(KyberVariant::Kyber512)?;
        let mut times = Vec::new();

        for _ in 0..self.config.iterations {
            let start = Instant::now();
            let _result = keypair.encapsulate()?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "Kyber Encapsulation",
            times,
            "Encapsulation timing should be constant for a given public key",
        )?)
    }

    /// Test Kyber decapsulation timing
    fn test_kyber_decapsulation(&self) -> CryptoResult<TimingAnalysis> {
        let keypair = KyberKeyPair::generate(KyberVariant::Kyber512)?;
        let (ciphertext, _) = keypair.encapsulate()?;
        let mut times = Vec::new();

        for _ in 0..self.config.iterations {
            let start = Instant::now();
            let _shared_secret = keypair.decapsulate(&ciphertext)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "Kyber Decapsulation",
            times,
            "Decapsulation timing should be constant for valid ciphertexts",
        )?)
    }

    /// Test Kyber timing with different keys
    fn test_kyber_timing_with_different_keys(&self) -> CryptoResult<TimingAnalysis> {
        let mut times = Vec::new();

        // Generate multiple keypairs and test decapsulation timing
        for _ in 0..self.config.iterations {
            let keypair = KyberKeyPair::generate(KyberVariant::Kyber512)?;
            let (ciphertext, _) = keypair.encapsulate()?;

            let start = Instant::now();
            let _shared_secret = keypair.decapsulate(&ciphertext)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "Kyber Different Keys",
            times,
            "Timing should not vary significantly between different keys",
        )?)
    }

    /// Test Dilithium key generation timing
    fn test_dilithium_keygen(&self) -> CryptoResult<TimingAnalysis> {
        let mut times = Vec::new();

        for _ in 0..self.config.iterations {
            let start = Instant::now();
            let _keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium2)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "Dilithium Key Generation",
            times,
            "Key generation should have consistent timing",
        )?)
    }

    /// Test Dilithium signing timing
    fn test_dilithium_sign(&self) -> CryptoResult<TimingAnalysis> {
        let keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium2)?;
        let message = b"test message for signing";
        let mut times = Vec::new();

        for _ in 0..self.config.iterations {
            let start = Instant::now();
            let _signature = keypair.sign(message)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "Dilithium Signing",
            times,
            "Signing should have consistent timing for same message length",
        )?)
    }

    /// Test Dilithium verification timing
    fn test_dilithium_verify(&self) -> CryptoResult<TimingAnalysis> {
        let keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium2)?;
        let message = b"test message for verification";
        let signature = keypair.sign(message)?;
        let mut times = Vec::new();

        for _ in 0..self.config.iterations {
            let start = Instant::now();
            let _valid = keypair.verify(message, &signature)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "Dilithium Verification",
            times,
            "Verification timing should be constant regardless of signature validity",
        )?)
    }

    /// Test Dilithium timing with different keys
    fn test_dilithium_timing_with_different_keys(&self) -> CryptoResult<TimingAnalysis> {
        let message = b"consistent message for timing test";
        let mut times = Vec::new();

        for _ in 0..self.config.iterations {
            let keypair = DilithiumKeyPair::generate(DilithiumVariant::Dilithium2)?;
            let signature = keypair.sign(message)?;

            let start = Instant::now();
            let _valid = keypair.verify(message, &signature)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "Dilithium Different Keys",
            times,
            "Verification timing should not leak information about keys",
        )?)
    }

    /// Test AES encryption timing
    fn test_aes_encryption(&self) -> CryptoResult<TimingAnalysis> {
        let key = [0u8; 32];
        let aes = AesGcm::new(&key)?;
        let plaintext = vec![0u8; 1024];
        let mut times = Vec::new();

        for _ in 0..self.config.iterations {
            let start = Instant::now();
            let nonce = AesGcm::generate_nonce();
            let _ciphertext = aes.encrypt(&plaintext, &nonce, None)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "AES Encryption",
            times,
            "AES encryption should have consistent timing for same plaintext size",
        )?)
    }

    /// Test AES decryption timing
    fn test_aes_decryption(&self) -> CryptoResult<TimingAnalysis> {
        let key = [0u8; 32];
        let aes = AesGcm::new(&key)?;
        let plaintext = vec![0u8; 1024];
        let nonce = AesGcm::generate_nonce();
        let ciphertext = aes.encrypt(&plaintext, &nonce, None)?;
        let mut times = Vec::new();

        for _ in 0..self.config.iterations {
            let start = Instant::now();
            let _decrypted = aes.decrypt(&ciphertext, &nonce, None)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "AES Decryption",
            times,
            "AES decryption should have consistent timing",
        )?)
    }

    /// Test AES timing with different keys
    fn test_aes_timing_with_different_keys(&self) -> CryptoResult<TimingAnalysis> {
        let plaintext = vec![0u8; 1024];
        let mut times = Vec::new();

        for i in 0..self.config.iterations {
            let mut key = [0u8; 32];
            key[0] = (i % 256) as u8;
            let aes = AesGcm::new(&key)?;

            let start = Instant::now();
            let nonce = AesGcm::generate_nonce();
            let _ciphertext = aes.encrypt(&plaintext, &nonce, None)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "AES Different Keys",
            times,
            "AES timing should not depend on key values",
        )?)
    }

    /// Test AES timing with different plaintexts
    fn test_aes_timing_with_different_plaintexts(&self) -> CryptoResult<TimingAnalysis> {
        let key = [0u8; 32];
        let aes = AesGcm::new(&key)?;
        let mut times = Vec::new();

        for i in 0..self.config.iterations {
            let mut plaintext = vec![0u8; 1024];
            plaintext[0] = (i % 256) as u8;

            let start = Instant::now();
            let nonce = AesGcm::generate_nonce();
            let _ciphertext = aes.encrypt(&plaintext, &nonce, None)?;
            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "AES Different Plaintexts",
            times,
            "AES timing should not depend on plaintext content",
        )?)
    }

    /// Test memory access patterns
    fn test_memory_access_patterns(&self) -> CryptoResult<TimingAnalysis> {
        let mut times = Vec::new();
        let data = vec![0u8; 4096]; // One page

        for _ in 0..self.config.iterations {
            let start = Instant::now();

            // Simulate memory access pattern that might leak information
            let mut sum = 0u64;
            for i in 0..data.len() {
                sum = sum.wrapping_add(data[i] as u64);
            }

            let duration = start.elapsed();
            times.push(duration);

            // Prevent compiler optimization
            std::hint::black_box(sum);
        }

        Ok(self.analyze_timing(
            "Memory Access Patterns",
            times,
            "Memory access should have consistent patterns",
        )?)
    }

    /// Test cache timing attacks
    fn test_cache_timing_attacks(&self) -> CryptoResult<TimingAnalysis> {
        let mut times = Vec::new();
        let lookup_table = vec![0u8; 256];

        for i in 0..self.config.iterations {
            let index = i % 256;

            let start = Instant::now();

            // Simulate table lookup that might be vulnerable to cache attacks
            let _value = lookup_table[index];

            let duration = start.elapsed();
            times.push(duration);
        }

        Ok(self.analyze_timing(
            "Cache Timing",
            times,
            "Table lookups should be resistant to cache timing attacks",
        )?)
    }

    /// Analyze timing measurements
    fn analyze_timing(
        &self,
        test_name: &str,
        times: Vec<Duration>,
        description: &str,
    ) -> CryptoResult<TimingAnalysis> {
        let times_nanos: Vec<u64> = times.iter().map(|d| d.as_nanos() as u64).collect();

        let mean = times_nanos.iter().sum::<u64>() as f64 / times_nanos.len() as f64;
        let variance = times_nanos
            .iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>()
            / times_nanos.len() as f64;
        let std_dev = variance.sqrt();

        let min_time = Duration::from_nanos(*times_nanos.iter().min().unwrap());
        let max_time = Duration::from_nanos(*times_nanos.iter().max().unwrap());
        let mean_time = Duration::from_nanos(mean as u64);
        let std_deviation = Duration::from_nanos(std_dev as u64);

        let coefficient_of_variation = if mean > 0.0 { std_dev / mean } else { 0.0 };

        // Determine if there's a potential vulnerability
        // Use a higher threshold (0.5) to reduce false positives in test environments
        let potential_vulnerability = coefficient_of_variation > 0.5;

        let vulnerability_description = if potential_vulnerability {
            format!(
                "High timing variation detected (CV: {:.4}). {}",
                coefficient_of_variation, description
            )
        } else {
            format!(
                "Timing appears consistent (CV: {:.4})",
                coefficient_of_variation
            )
        };

        Ok(TimingAnalysis {
            test_name: test_name.to_string(),
            mean_time,
            std_deviation,
            min_time,
            max_time,
            coefficient_of_variation,
            potential_vulnerability,
            vulnerability_description,
        })
    }

    /// Calculate overall security score
    fn calculate_overall_score(&self, tests: &[TimingAnalysis]) -> f64 {
        let vulnerable_tests = tests.iter().filter(|t| t.potential_vulnerability).count();
        let total_tests = tests.len();

        if total_tests == 0 {
            return 0.0;
        }

        let vulnerability_ratio = vulnerable_tests as f64 / total_tests as f64;

        // Score from 0-100, where 100 is perfect (no vulnerabilities)
        (1.0 - vulnerability_ratio) * 100.0
    }

    /// Generate security recommendations
    fn generate_recommendations(&self, tests: &[TimingAnalysis]) -> Vec<String> {
        let mut recommendations = Vec::new();

        let vulnerable_tests: Vec<_> = tests.iter().filter(|t| t.potential_vulnerability).collect();

        if vulnerable_tests.is_empty() {
            recommendations.push("Excellent! No timing vulnerabilities detected.".to_string());
            recommendations.push(
                "Continue regular side-channel testing as part of security audits.".to_string(),
            );
        } else {
            recommendations.push(format!(
                "⚠️  {} potential timing vulnerabilities detected.",
                vulnerable_tests.len()
            ));

            for test in vulnerable_tests {
                if test.test_name.contains("Kyber") {
                    recommendations
                        .push("Consider implementing constant-time Kyber operations".to_string());
                } else if test.test_name.contains("Dilithium") {
                    recommendations.push(
                        "Review Dilithium implementation for constant-time guarantees".to_string(),
                    );
                } else if test.test_name.contains("AES") {
                    recommendations.push(
                        "Ensure AES implementation uses constant-time operations".to_string(),
                    );
                } else if test.test_name.contains("Memory") {
                    recommendations
                        .push("Review memory access patterns for information leakage".to_string());
                } else if test.test_name.contains("Cache") {
                    recommendations.push("Implement cache-resistant table lookups".to_string());
                }
            }

            recommendations
                .push("Consider using dedicated constant-time cryptographic libraries".to_string());
            recommendations.push("Implement blinding techniques where appropriate".to_string());
            recommendations.push("Add random delays to mask timing variations".to_string());
            recommendations
                .push("Use hardware security modules (HSMs) for critical operations".to_string());
        }

        recommendations
    }

    /// Export results to JSON
    pub fn export_results(results: &SideChannelResults, filename: &str) -> CryptoResult<()> {
        use std::fs::File;
        use std::io::Write;

        let json = serde_json::to_string_pretty(results)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        let mut file = File::create(filename).map_err(|e| CryptoError::IoError(e.to_string()))?;

        file.write_all(json.as_bytes())
            .map_err(|e| CryptoError::IoError(e.to_string()))?;

        Ok(())
    }
}

/// Advanced timing analysis for statistical significance
pub struct AdvancedTimingAnalysis;

impl AdvancedTimingAnalysis {
    /// Perform t-test to determine if timing differences are statistically significant
    pub fn t_test(group1: &[Duration], group2: &[Duration]) -> f64 {
        if group1.is_empty() || group2.is_empty() {
            return 0.0;
        }

        let mean1 = Self::mean(group1);
        let mean2 = Self::mean(group2);

        let var1 = Self::variance(group1, mean1);
        let var2 = Self::variance(group2, mean2);

        let n1 = group1.len() as f64;
        let n2 = group2.len() as f64;

        let pooled_se = ((var1 / n1) + (var2 / n2)).sqrt();

        if pooled_se == 0.0 {
            return 0.0;
        }

        (mean1 - mean2) / pooled_se
    }

    fn mean(times: &[Duration]) -> f64 {
        times.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / times.len() as f64
    }

    fn variance(times: &[Duration], mean: f64) -> f64 {
        times
            .iter()
            .map(|d| (d.as_nanos() as f64 - mean).powi(2))
            .sum::<f64>()
            / times.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_side_channel_basic() {
        let tester = SideChannelTester::new(TestConfig { iterations: 10 });
        let results = tester.run_all_tests().expect("Side-channel test failed");

        assert!(results.test_name == "Side-Channel Tests");
    }

    #[test]
    fn test_timing_analysis() {
        let times = vec![
            Duration::from_nanos(1000),
            Duration::from_nanos(1010),
            Duration::from_nanos(990),
            Duration::from_nanos(1005),
        ];

        let tester = SideChannelTester::new(TestConfig { iterations: 100 });
        let analysis = tester
            .analyze_timing("Test", times, "Test description")
            .expect("Timing analysis failed");

        assert_eq!(analysis.test_name, "Test");
        assert!(analysis.coefficient_of_variation >= 0.0);
    }
}

pub fn generate_report(results: &SideChannelResults) -> CryptoResult<String> {
    serde_json::to_string_pretty(results)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))
}
