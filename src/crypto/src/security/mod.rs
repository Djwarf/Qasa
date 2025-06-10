/*!
 * Security Module for QaSa Cryptography
 *
 * Provides constant-time verification, side-channel resistance testing,
 * and security policy enforcement as per the improvement roadmap.
 */

pub mod constant_time;
pub mod side_channel;
pub mod audit;
pub mod policy;

// Re-export main types for convenience
pub use constant_time::{ConstantTime, verify_constant_time, ConstantTimeResult};
pub use side_channel::{SideChannelTester, TimingAnalyzer, TimingAnalysisResult};
pub use audit::{SecurityEvent, SecurityAuditor, Auditable};
pub use policy::{SecurityPolicy, SecurityPolicyEnforcer}; 