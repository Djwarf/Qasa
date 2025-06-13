/*!
 * Security Module for QaSa Cryptography
 *
 * Provides constant-time verification, side-channel resistance testing,
 * and security policy enforcement as per the improvement roadmap.
 */

pub mod audit;
pub mod constant_time;
pub mod policy;
pub mod side_channel;

// Re-export main types for convenience
pub use audit::{Auditable, SecurityAuditor, SecurityEvent};
pub use constant_time::{verify_constant_time, ConstantTime, ConstantTimeResult};
pub use policy::{SecurityPolicy, SecurityPolicyEnforcer};
pub use side_channel::{SideChannelTester, TimingAnalysisResult, TimingAnalyzer};
