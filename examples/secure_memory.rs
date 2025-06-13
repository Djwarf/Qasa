//! Example: Secure Memory and Constant-Time Comparison
use qasa::utils::{secure_zero, constant_time_eq};

fn main() {
    let mut sensitive = vec![1u8, 2, 3, 4, 5];
    let compare = vec![1u8, 2, 3, 4, 5];
    let wrong = vec![1u8, 2, 3, 4, 9];

    // Constant-time comparison
    assert!(constant_time_eq(&sensitive, &compare));
    assert!(!constant_time_eq(&sensitive, &wrong));
    println!("Constant-time comparison works as expected.");

    // Secure zeroization
    secure_zero(&mut sensitive);
    assert!(sensitive.iter().all(|&b| b == 0));
    println!("Sensitive data securely zeroized.");
} 