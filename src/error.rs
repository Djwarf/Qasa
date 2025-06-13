/*!
 * Enhanced Error Handling for QaSa Cryptography Module
 *
 * Provides comprehensive error types with detailed diagnostics, error codes,
 * user-friendly messages, and suggested remediation strategies.
 */

use std::collections::HashMap;
use thiserror::Error;

/// Comprehensive error type for all cryptographic operations
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Kyber operation failed: {operation} - {cause}")]
    KyberError {
        operation: String,
        cause: String,
        error_code: u32,
        context: HashMap<String, String>,
    },

    #[error("Dilithium operation failed: {operation} - {cause}")]
    DilithiumError {
        operation: String,
        cause: String,
        error_code: u32,
        context: HashMap<String, String>,
    },

    #[error("AES operation failed: {operation} - {cause}")]
    AesError {
        operation: String,
        cause: String,
        error_code: u32,
        context: HashMap<String, String>,
    },

    #[error("Key management error: {operation} - {cause}")]
    KeyManagementError {
        operation: String,
        cause: String,
        error_code: u32,
        context: HashMap<String, String>,
    },

    #[error("Security policy violation: {policy} - {details}")]
    SecurityPolicyViolation {
        policy: String,
        details: String,
        error_code: u32,
        severity: SecuritySeverity,
    },

    #[error("Memory operation failed: {operation} - {cause}")]
    MemoryError {
        operation: String,
        cause: String,
        error_code: u32,
    },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Random number generation failed: {cause}")]
    RandomGenerationError { cause: String, error_code: u32 },

    #[error("Hardware acceleration error: {operation} - {cause}")]
    HardwareAccelerationError {
        operation: String,
        cause: String,
        error_code: u32,
    },

    #[error("Protocol error: {protocol} - {phase} - {cause}")]
    ProtocolError {
        protocol: String,
        phase: String,
        cause: String,
        error_code: u32,
    },

    #[error("Side-channel protection failure: {test_name} - {details}")]
    SideChannelViolation {
        test_name: String,
        details: String,
        error_code: u32,
    },

    #[error("Formal verification failed: {property} - {details}")]
    FormalVerificationError {
        property: String,
        details: String,
        error_code: u32,
    },

    #[error("Invalid parameter: {parameter} - {expected} - got {actual}")]
    InvalidParameter {
        parameter: String,
        expected: String,
        actual: String,
        error_code: u32,
    },

    #[error("Operation not supported: {operation} on {platform}")]
    UnsupportedOperation {
        operation: String,
        platform: String,
        error_code: u32,
    },

    #[error("Resource exhaustion: {resource} - {limit}")]
    ResourceExhaustion {
        resource: String,
        limit: String,
        error_code: u32,
    },

    #[error("IO error: {0}")]
    IoError(String),

    #[error("OQS library error: {0}")]
    OqsError(String),
}

/// Security severity levels for policy violations
#[derive(Debug, Clone, PartialEq)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Error code constants for different error categories
pub mod error_codes {
    // Kyber errors: 1000-1999
    pub const KYBER_INITIALIZATION_FAILED: u32 = 1000;
    pub const KYBER_KEY_GENERATION_FAILED: u32 = 1001;
    pub const KYBER_ENCAPSULATION_FAILED: u32 = 1002;
    pub const KYBER_DECAPSULATION_FAILED: u32 = 1003;
    pub const KYBER_INVALID_KEY_SIZE: u32 = 1004;
    pub const KYBER_INVALID_CIPHERTEXT: u32 = 1005;
    pub const KYBER_INSUFFICIENT_MEMORY: u32 = 1006;

    // Dilithium errors: 2000-2999
    pub const DILITHIUM_KEY_GENERATION_FAILED: u32 = 2001;
    pub const DILITHIUM_SIGNING_FAILED: u32 = 2002;
    pub const DILITHIUM_VERIFICATION_FAILED: u32 = 2003;
    pub const DILITHIUM_INVALID_SIGNATURE: u32 = 2004;
    pub const DILITHIUM_INVALID_KEY_SIZE: u32 = 2005;
    pub const DILITHIUM_COMPRESSION_FAILED: u32 = 2006;
    pub const DILITHIUM_DECOMPRESSION_FAILED: u32 = 2007;

    // AES errors: 3000-3999
    pub const AES_ENCRYPTION_FAILED: u32 = 3001;
    pub const AES_DECRYPTION_FAILED: u32 = 3002;
    pub const AES_INVALID_KEY_SIZE: u32 = 3003;
    pub const AES_INVALID_NONCE_SIZE: u32 = 3004;
    pub const AES_AUTHENTICATION_FAILED: u32 = 3005;

    // Key management errors: 4000-4999
    pub const KEY_STORAGE_FAILED: u32 = 4001;
    pub const KEY_RETRIEVAL_FAILED: u32 = 4002;
    pub const KEY_ROTATION_FAILED: u32 = 4003;
    pub const INVALID_PASSWORD: u32 = 4004;
    pub const KEY_DERIVATION_FAILED: u32 = 4005;

    // Security policy errors: 5000-5999
    pub const SECURITY_POLICY_VIOLATION: u32 = 5001;
    pub const INSUFFICIENT_ENTROPY: u32 = 5002;
    pub const TIMING_ATTACK_DETECTED: u32 = 5003;
    pub const SIDE_CHANNEL_LEAK: u32 = 5004;
    pub const FORMAL_VERIFICATION_FAILED: u32 = 5005;

    // Memory errors: 6000-6999
    pub const MEMORY_ALLOCATION_FAILED: u32 = 6001;
    pub const SECURE_MEMORY_LOCK_FAILED: u32 = 6002;
    pub const MEMORY_ZEROIZATION_FAILED: u32 = 6003;

    // Hardware errors: 7000-7999
    pub const SIMD_NOT_AVAILABLE: u32 = 7001;
    pub const HARDWARE_RNG_FAILED: u32 = 7002;
    pub const HSM_OPERATION_FAILED: u32 = 7003;

    // Protocol errors: 8000-8999
    pub const PROTOCOL_HANDSHAKE_FAILED: u32 = 8001;
    pub const PROTOCOL_STATE_INVALID: u32 = 8002;
    pub const PROTOCOL_VERSION_MISMATCH: u32 = 8003;
}

impl CryptoError {
    /// Get the numeric error code for this error
    pub fn error_code(&self) -> u32 {
        match self {
            CryptoError::KyberError { error_code, .. } => *error_code,
            CryptoError::DilithiumError { error_code, .. } => *error_code,
            CryptoError::AesError { error_code, .. } => *error_code,
            CryptoError::KeyManagementError { error_code, .. } => *error_code,
            CryptoError::SecurityPolicyViolation { error_code, .. } => *error_code,
            CryptoError::MemoryError { error_code, .. } => *error_code,
            CryptoError::RandomGenerationError { error_code, .. } => *error_code,
            CryptoError::HardwareAccelerationError { error_code, .. } => *error_code,
            CryptoError::ProtocolError { error_code, .. } => *error_code,
            CryptoError::SideChannelViolation { error_code, .. } => *error_code,
            CryptoError::FormalVerificationError { error_code, .. } => *error_code,
            CryptoError::InvalidParameter { error_code, .. } => *error_code,
            CryptoError::UnsupportedOperation { error_code, .. } => *error_code,
            CryptoError::ResourceExhaustion { error_code, .. } => *error_code,
            CryptoError::SerializationError(_) => 9001,
            CryptoError::IoError(_) => 9002,
            CryptoError::OqsError(_) => 9003,
        }
    }

    /// Get a user-friendly error message
    pub fn user_friendly_message(&self) -> String {
        match self {
            CryptoError::KyberError { operation, .. } => {
                format!("Key exchange operation '{}' failed. This may affect secure communication setup.", operation)
            }
            CryptoError::DilithiumError { operation, .. } => {
                format!("Digital signature operation '{}' failed. Message authenticity cannot be verified.", operation)
            }
            CryptoError::AesError { operation, .. } => {
                format!(
                    "Encryption operation '{}' failed. Data security may be compromised.",
                    operation
                )
            }
            CryptoError::KeyManagementError { operation, .. } => {
                format!("Key management operation '{}' failed. Secure key storage or retrieval is not available.", operation)
            }
            CryptoError::SecurityPolicyViolation {
                policy, severity, ..
            } => match severity {
                SecuritySeverity::Critical => format!(
                    "Critical security violation: {}. Immediate action required.",
                    policy
                ),
                SecuritySeverity::High => format!(
                    "High-priority security issue: {}. Please address promptly.",
                    policy
                ),
                SecuritySeverity::Medium => {
                    format!("Security concern: {}. Review recommended.", policy)
                }
                SecuritySeverity::Low => format!("Minor security notice: {}.", policy),
            },
            CryptoError::MemoryError { operation, .. } => {
                format!(
                    "Memory operation '{}' failed. System may be low on secure memory.",
                    operation
                )
            }
            CryptoError::RandomGenerationError { .. } => {
                "Random number generation failed. Cryptographic operations may be insecure."
                    .to_string()
            }
            CryptoError::HardwareAccelerationError { operation, .. } => {
                format!("Hardware acceleration for '{}' failed. Falling back to software implementation.", operation)
            }
            CryptoError::ProtocolError {
                protocol, phase, ..
            } => {
                format!("Protocol '{}' failed during '{}' phase. Secure communication cannot be established.", protocol, phase)
            }
            CryptoError::SideChannelViolation { test_name, .. } => {
                format!(
                    "Side-channel vulnerability detected in '{}'. Security may be compromised.",
                    test_name
                )
            }
            CryptoError::FormalVerificationError { property, .. } => {
                format!("Formal verification failed for property '{}'. Code correctness cannot be guaranteed.", property)
            }
            CryptoError::InvalidParameter {
                parameter,
                expected,
                ..
            } => {
                format!(
                    "Invalid parameter '{}'. Expected '{}' format.",
                    parameter, expected
                )
            }
            CryptoError::UnsupportedOperation {
                operation,
                platform,
                ..
            } => {
                format!(
                    "Operation '{}' is not supported on '{}' platform.",
                    operation, platform
                )
            }
            CryptoError::ResourceExhaustion { resource, .. } => {
                format!(
                    "System resource '{}' exhausted. Performance may be degraded.",
                    resource
                )
            }
            CryptoError::SerializationError(_) => {
                "Data serialization failed. Data format may be corrupted.".to_string()
            }
            CryptoError::IoError(_) => {
                "Input/output operation failed. Check file permissions and disk space.".to_string()
            }
            CryptoError::OqsError(_) => {
                "OQS library error. Check library version and configuration.".to_string()
            }
        }
    }

    /// Get technical details for debugging
    pub fn technical_details(&self) -> HashMap<String, String> {
        let mut details = HashMap::new();

        details.insert("error_code".to_string(), self.error_code().to_string());
        details.insert("error_type".to_string(), self.error_type().to_string());
        details.insert("timestamp".to_string(), chrono::Utc::now().to_rfc3339());

        match self {
            CryptoError::KyberError {
                operation,
                cause,
                context,
                ..
            } => {
                details.insert("operation".to_string(), operation.clone());
                details.insert("cause".to_string(), cause.clone());
                details.extend(context.clone());
            }
            CryptoError::DilithiumError {
                operation,
                cause,
                context,
                ..
            } => {
                details.insert("operation".to_string(), operation.clone());
                details.insert("cause".to_string(), cause.clone());
                details.extend(context.clone());
            }
            CryptoError::AesError {
                operation,
                cause,
                context,
                ..
            } => {
                details.insert("operation".to_string(), operation.clone());
                details.insert("cause".to_string(), cause.clone());
                details.extend(context.clone());
            }
            CryptoError::KeyManagementError {
                operation,
                cause,
                context,
                ..
            } => {
                details.insert("operation".to_string(), operation.clone());
                details.insert("cause".to_string(), cause.clone());
                details.extend(context.clone());
            }
            CryptoError::SecurityPolicyViolation {
                policy,
                details: policy_details,
                severity,
                ..
            } => {
                details.insert("policy".to_string(), policy.clone());
                details.insert("policy_details".to_string(), policy_details.clone());
                details.insert("severity".to_string(), format!("{:?}", severity));
            }
            CryptoError::InvalidParameter {
                parameter,
                expected,
                actual,
                ..
            } => {
                details.insert("parameter".to_string(), parameter.clone());
                details.insert("expected".to_string(), expected.clone());
                details.insert("actual".to_string(), actual.clone());
            }
            _ => {
                details.insert("details".to_string(), format!("{:?}", self));
            }
        }

        details
    }

    /// Get suggested remediation steps
    pub fn suggested_remediation(&self) -> Option<String> {
        match self {
            CryptoError::KyberError { error_code, .. } => match *error_code {
                error_codes::KYBER_KEY_GENERATION_FAILED => Some(
                    "Ensure sufficient entropy is available. Check system random number generator."
                        .to_string(),
                ),
                error_codes::KYBER_INVALID_KEY_SIZE => Some(
                    "Use a supported Kyber variant (Kyber512, Kyber768, or Kyber1024).".to_string(),
                ),
                _ => Some("Check Kyber algorithm parameters and input data validity.".to_string()),
            },
            CryptoError::DilithiumError { error_code, .. } => match *error_code {
                error_codes::DILITHIUM_VERIFICATION_FAILED => Some(
                    "Verify the signature and public key are correct. Check for data tampering."
                        .to_string(),
                ),
                error_codes::DILITHIUM_INVALID_KEY_SIZE => Some(
                    "Use a supported Dilithium variant (Dilithium2, Dilithium3, or Dilithium5)."
                        .to_string(),
                ),
                _ => Some(
                    "Check Dilithium algorithm parameters and input data validity.".to_string(),
                ),
            },
            CryptoError::SecurityPolicyViolation { severity, .. } => match severity {
                SecuritySeverity::Critical => Some(
                    "Immediately stop current operation and review security configuration."
                        .to_string(),
                ),
                SecuritySeverity::High => {
                    Some("Review and update security policies. Consider system audit.".to_string())
                }
                _ => Some("Review security configuration and update as needed.".to_string()),
            },
            CryptoError::RandomGenerationError { .. } => Some(
                "Check system entropy sources. Consider using hardware RNG if available."
                    .to_string(),
            ),
            CryptoError::MemoryError { .. } => Some(
                "Check available system memory. Consider reducing concurrent operations."
                    .to_string(),
            ),
            CryptoError::HardwareAccelerationError { .. } => Some(
                "Hardware acceleration failed. Software fallback will be used automatically."
                    .to_string(),
            ),
            CryptoError::UnsupportedOperation { .. } => Some(
                "Use platform-specific alternatives or update to a supported platform.".to_string(),
            ),
            _ => None,
        }
    }

    /// Get the error category/type as a string
    pub fn error_type(&self) -> &'static str {
        match self {
            CryptoError::KyberError { .. } => "KyberError",
            CryptoError::DilithiumError { .. } => "DilithiumError",
            CryptoError::AesError { .. } => "AesError",
            CryptoError::KeyManagementError { .. } => "KeyManagementError",
            CryptoError::SecurityPolicyViolation { .. } => "SecurityPolicyViolation",
            CryptoError::MemoryError { .. } => "MemoryError",
            CryptoError::SerializationError { .. } => "SerializationError",
            CryptoError::RandomGenerationError { .. } => "RandomGenerationError",
            CryptoError::HardwareAccelerationError { .. } => "HardwareAccelerationError",
            CryptoError::ProtocolError { .. } => "ProtocolError",
            CryptoError::SideChannelViolation { .. } => "SideChannelViolation",
            CryptoError::FormalVerificationError { .. } => "FormalVerificationError",
            CryptoError::InvalidParameter { .. } => "InvalidParameter",
            CryptoError::UnsupportedOperation { .. } => "UnsupportedOperation",
            CryptoError::ResourceExhaustion { .. } => "ResourceExhaustion",
            CryptoError::IoError { .. } => "IoError",
            CryptoError::OqsError { .. } => "OqsError",
        }
    }
}

/// Convenience constructors for common error types
impl CryptoError {
    pub fn kyber_error(operation: &str, cause: &str, error_code: u32) -> Self {
        CryptoError::KyberError {
            operation: operation.to_string(),
            cause: cause.to_string(),
            error_code,
            context: HashMap::new(),
        }
    }

    pub fn dilithium_error(operation: &str, cause: &str, error_code: u32) -> Self {
        CryptoError::DilithiumError {
            operation: operation.to_string(),
            cause: cause.to_string(),
            error_code,
            context: HashMap::new(),
        }
    }

    pub fn aes_error(operation: &str, cause: &str, error_code: u32) -> Self {
        CryptoError::AesError {
            operation: operation.to_string(),
            cause: cause.to_string(),
            error_code,
            context: HashMap::new(),
        }
    }

    pub fn security_violation(policy: &str, details: &str, severity: SecuritySeverity) -> Self {
        CryptoError::SecurityPolicyViolation {
            policy: policy.to_string(),
            details: details.to_string(),
            error_code: error_codes::SECURITY_POLICY_VIOLATION,
            severity,
        }
    }

    pub fn invalid_parameter(parameter: &str, expected: &str, actual: &str) -> Self {
        CryptoError::InvalidParameter {
            parameter: parameter.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
            error_code: 9999,
        }
    }

    pub fn key_management_error(operation: &str, cause: &str, key_type: &str) -> Self {
        let mut context = HashMap::new();
        context.insert("key_type".to_string(), key_type.to_string());

        CryptoError::KeyManagementError {
            operation: operation.to_string(),
            cause: cause.to_string(),
            error_code: error_codes::KEY_STORAGE_FAILED,
            context,
        }
    }

    pub fn io_error(cause: &str, error_code: u32) -> Self {
        CryptoError::IoError(cause.to_string())
    }
}

// From implementations for automatic error conversion
impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::io_error(&format!("IO operation failed: {}", err), 8001)
    }
}

impl From<oqs::Error> for CryptoError {
    fn from(err: oqs::Error) -> Self {
        CryptoError::OqsError(err.to_string())
    }
}

/// Result type alias for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_generation() {
        let error = CryptoError::kyber_error(
            "key_generation",
            "RNG failed",
            error_codes::KYBER_KEY_GENERATION_FAILED,
        );
        assert_eq!(error.error_code(), error_codes::KYBER_KEY_GENERATION_FAILED);
    }

    #[test]
    fn test_user_friendly_message() {
        let error = CryptoError::security_violation(
            "constant_time",
            "Timing leak detected",
            SecuritySeverity::Critical,
        );
        let message = error.user_friendly_message();
        assert!(message.contains("Critical security violation"));
    }

    #[test]
    fn test_technical_details() {
        let error = CryptoError::dilithium_error(
            "signing",
            "Invalid key format",
            error_codes::DILITHIUM_SIGNING_FAILED,
        );
        let details = error.technical_details();
        assert!(details.contains_key("error_code"));
        assert!(details.contains_key("operation"));
        assert!(details.contains_key("cause"));
    }

    #[test]
    fn test_remediation_suggestions() {
        let error = CryptoError::RandomGenerationError {
            cause: "Insufficient entropy".to_string(),
            error_code: error_codes::INSUFFICIENT_ENTROPY,
        };
        let suggestion = error.suggested_remediation();
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("entropy"));
    }
}
