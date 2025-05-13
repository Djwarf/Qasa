/*!
 * Key Management System for cryptographic keys
 *
 * This module implements secure key storage and management functions
 * for the quantum-resistant and symmetric keys used in the application.
 */

// Key management functionality for storing and loading keys

// Re-export password module for external use
pub mod password;
pub mod storage;
pub mod rotation;

#[cfg(test)]
mod tests;

pub use password::DerivedKey;
pub use password::KeyDerivationParams;
pub use password::derive_key_from_password;
pub use password::verify_password;
pub use password::change_password;
pub use rotation::RotationPolicy;
pub use rotation::KeyRotationMetadata;
pub use rotation::KeyAgeSummary;
pub use rotation::rotate_kyber_keypair;
pub use rotation::rotate_dilithium_keypair;
pub use rotation::get_key_age;
pub use rotation::check_keys_for_rotation;
pub use rotation::auto_rotate_keys;
pub use rotation::get_all_key_ages_internal;
pub use storage::store_kyber_keypair;
pub use storage::load_kyber_keypair;
pub use storage::store_dilithium_keypair;
pub use storage::load_dilithium_keypair;
pub use storage::list_keys;
pub use storage::delete_key;
pub use storage::export_key;
pub use storage::import_key;
