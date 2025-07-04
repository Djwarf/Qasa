/*!
 * Security Audit Framework
 */

use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: SystemTime,
    pub event_type: String,
    pub details: HashMap<String, String>,
}

pub trait Auditable {
    fn log_security_event(&self, event: SecurityEvent);
}

#[derive(Debug)]
pub struct SecurityAuditor {
    events: Vec<SecurityEvent>,
}

impl SecurityAuditor {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn log_event(&mut self, event: SecurityEvent) {
        self.events.push(event);
    }

    pub fn get_events(&self) -> &[SecurityEvent] {
        &self.events
    }
}
