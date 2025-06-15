/*!
 * Security Policy Framework
 */

use crate::error::CryptoResult;

#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug)]
pub struct SecurityPolicyEnforcer {
    policies: Vec<SecurityPolicy>,
}

impl SecurityPolicyEnforcer {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn add_policy(&mut self, policy: SecurityPolicy) {
        self.policies.push(policy);
    }

    pub fn enforce_policies(&self) -> CryptoResult<()> {
        // Check if all required policies are enabled
        for policy in &self.policies {
            if !policy.enabled {
                return Err(crate::error::CryptoError::authentication_error(
                    "policy_enforcement",
                    &format!("Required security policy '{}' is not enabled", policy.name),
                    crate::error::error_codes::AES_AUTHENTICATION_FAILED,
                ));
            }
        }
        
        // All policies are enabled
        Ok(())
    }
}
