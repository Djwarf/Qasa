#[cfg(test)]
#[cfg(feature = "constant-time-testing")]
mod tests {
    use qasa::kyber::{KyberKeyPair, KyberVariant};
    use qasa::security::constant_time::ConstantTimeConfig;

    #[test]
    fn test_kyber_constant_time_methods_exist() {
        let config = ConstantTimeConfig::default();
        
        // Test that the methods exist and can be called
        let result = KyberKeyPair::generate_test_constant_time(KyberVariant::Kyber768, &config);
        assert!(result.is_ok());
        
        println!("Kyber constant-time methods work!");
    }
}
