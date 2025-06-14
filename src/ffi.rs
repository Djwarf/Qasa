/*!
 * FFI interface for the crypto module
 *
 * This module provides C-compatible functions for using the crypto module from other languages.
 */

// Allow pointer dereferencing in FFI functions as we guarantee proper checks and safety
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::CString;
use std::slice;

use crate::aes;
use crate::dilithium::{DilithiumKeyPair, DilithiumVariant};
use crate::error::CryptoError;
use crate::kyber::{KyberKeyPair, KyberVariant};
use libc::{c_char, c_int};

// Python FFI support
#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::wrap_pyfunction;
    use pyo3::types::PyBytes;
    use pyo3::exceptions::{PyValueError, PyRuntimeError};
    
    use crate::kyber::{KyberKeyPair, KyberVariant};
    use crate::dilithium::{DilithiumKeyPair, DilithiumVariant};
    use crate::error::CryptoError;
    
    /// Convert a Rust Result to a Python Result
    fn to_py_result<T>(result: Result<T, CryptoError>) -> PyResult<T> {
        result.map_err(|e| PyValueError::new_err(e.to_string()))
    }
    
    /// Python module for QaSa cryptography
    #[pymodule]
    fn qasa(_py: Python, m: &PyModule) -> PyResult<()> {
        // Initialize the module
        m.add_function(wrap_pyfunction!(init, m)?)?;
        
        // Kyber functions
        m.add_function(wrap_pyfunction!(kyber_keygen, m)?)?;
        m.add_function(wrap_pyfunction!(kyber_encapsulate, m)?)?;
        m.add_function(wrap_pyfunction!(kyber_decapsulate, m)?)?;
        
        // Dilithium functions
        m.add_function(wrap_pyfunction!(dilithium_keygen, m)?)?;
        m.add_function(wrap_pyfunction!(dilithium_sign, m)?)?;
        m.add_function(wrap_pyfunction!(dilithium_verify, m)?)?;
        
        // SPHINCS+ functions
        m.add_function(wrap_pyfunction!(sphincs_keygen, m)?)?;
        m.add_function(wrap_pyfunction!(sphincs_sign, m)?)?;
        m.add_function(wrap_pyfunction!(sphincs_verify, m)?)?;
        m.add_function(wrap_pyfunction!(sphincs_sign_compressed, m)?)?;
        
        // AES functions
        m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
        m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;
        
        Ok(())
    }
    
    /// Initialize the cryptography module
    #[pyfunction]
    fn init() -> PyResult<()> {
        to_py_result(crate::init())
    }
    
    /// Generate a Kyber key pair
    #[pyfunction]
    fn kyber_keygen(variant: u32) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let kyber_variant = match variant {
            512 => KyberVariant::Kyber512,
            768 => KyberVariant::Kyber768,
            1024 => KyberVariant::Kyber1024,
            _ => return Err(PyValueError::new_err(format!("Invalid Kyber variant: {}", variant))),
        };
        
        let key_pair = to_py_result(KyberKeyPair::generate(kyber_variant))?;
        Ok((key_pair.public_key, key_pair.secret_key))
    }
    
    /// Encapsulate a shared secret using a Kyber public key
    #[pyfunction]
    fn kyber_encapsulate(variant: u32, public_key: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let kyber_variant = match variant {
            512 => KyberVariant::Kyber512,
            768 => KyberVariant::Kyber768,
            1024 => KyberVariant::Kyber1024,
            _ => return Err(PyValueError::new_err(format!("Invalid Kyber variant: {}", variant))),
        };
        
        let result = to_py_result(KyberKeyPair::encapsulate_with_public_key(
            kyber_variant,
            &public_key,
        ))?;
        
        Ok((result.0, result.1))
    }
    
    /// Decapsulate a shared secret using a Kyber secret key
    #[pyfunction]
    fn kyber_decapsulate(variant: u32, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> PyResult<Vec<u8>> {
        let kyber_variant = match variant {
            512 => KyberVariant::Kyber512,
            768 => KyberVariant::Kyber768,
            1024 => KyberVariant::Kyber1024,
            _ => return Err(PyValueError::new_err(format!("Invalid Kyber variant: {}", variant))),
        };
        
        let result = to_py_result(KyberKeyPair::decapsulate_with_secret_key(
            kyber_variant,
            &secret_key,
            &ciphertext,
        ))?;
        
        Ok(result)
    }
    
    /// Generate a Dilithium key pair
    #[pyfunction]
    fn dilithium_keygen(variant: u32) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let dilithium_variant = match variant {
            2 => DilithiumVariant::Dilithium2,
            3 => DilithiumVariant::Dilithium3,
            5 => DilithiumVariant::Dilithium5,
            _ => return Err(PyValueError::new_err(format!("Invalid Dilithium variant: {}", variant))),
        };
        
        let key_pair = to_py_result(DilithiumKeyPair::generate(dilithium_variant))?;
        Ok((key_pair.public_key, key_pair.secret_key))
    }
    
    /// Sign a message using a Dilithium secret key
    #[pyfunction]
    fn dilithium_sign(variant: u32, secret_key: Vec<u8>, message: Vec<u8>) -> PyResult<Vec<u8>> {
        let dilithium_variant = match variant {
            2 => DilithiumVariant::Dilithium2,
            3 => DilithiumVariant::Dilithium3,
            5 => DilithiumVariant::Dilithium5,
            _ => return Err(PyValueError::new_err(format!("Invalid Dilithium variant: {}", variant))),
        };
        
        let key_pair = DilithiumKeyPair {
            public_key: Vec::new(), // Not needed for signing
            secret_key,
            algorithm: dilithium_variant,
        };
        
        to_py_result(key_pair.sign(&message))
    }
    
    /// Verify a signature using a Dilithium public key
    #[pyfunction]
    fn dilithium_verify(variant: u32, public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        let dilithium_variant = match variant {
            2 => DilithiumVariant::Dilithium2,
            3 => DilithiumVariant::Dilithium3,
            5 => DilithiumVariant::Dilithium5,
            _ => return Err(PyValueError::new_err(format!("Invalid Dilithium variant: {}", variant))),
        };
        
        to_py_result(DilithiumKeyPair::verify_with_public_key(
            dilithium_variant,
            &public_key,
            &message,
            &signature,
        ))
    }
    
    /// Encrypt data using AES-GCM
    #[pyfunction]
    fn aes_gcm_encrypt(key: Vec<u8>, plaintext: Vec<u8>, associated_data: Option<Vec<u8>>) -> PyResult<(Vec<u8>, Vec<u8>)> {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(PyValueError::new_err("AES key must be 16, 24, or 32 bytes"));
        }
        
        let aes = to_py_result(crate::aes::AesGcm::new(&key))?;
        let nonce = crate::aes::AesGcm::generate_nonce();
        
        let ad_ref = associated_data.as_deref();
        let ciphertext = to_py_result(aes.encrypt(&plaintext, &nonce, ad_ref))?;
        
        Ok((ciphertext, nonce.to_vec()))
    }
    
    /// Decrypt data using AES-GCM
    #[pyfunction]
    fn aes_gcm_decrypt(key: Vec<u8>, ciphertext: Vec<u8>, nonce: Vec<u8>, associated_data: Option<Vec<u8>>) -> PyResult<Vec<u8>> {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(PyValueError::new_err("AES key must be 16, 24, or 32 bytes"));
        }
        
        if nonce.len() != 12 {
            return Err(PyValueError::new_err("AES-GCM nonce must be 12 bytes"));
        }
        
        let aes = to_py_result(crate::aes::AesGcm::new(&key))?;
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(&nonce);
        
        let ad_ref = associated_data.as_deref();
        to_py_result(aes.decrypt(&ciphertext, &nonce_array, ad_ref))
    }
    
    /// Generate a SPHINCS+ key pair
    #[pyfunction]
    fn sphincs_keygen(variant: u32) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let sphincs_variant = match variant {
            128 => crate::sphincsplus::SphincsVariant::Sphincs128f,
            129 => crate::sphincsplus::SphincsVariant::Sphincs128s,
            192 => crate::sphincsplus::SphincsVariant::Sphincs192f,
            193 => crate::sphincsplus::SphincsVariant::Sphincs192s,
            256 => crate::sphincsplus::SphincsVariant::Sphincs256f,
            257 => crate::sphincsplus::SphincsVariant::Sphincs256s,
            _ => return Err(PyValueError::new_err(format!("Invalid SPHINCS+ variant: {}", variant))),
        };
        
        let key_pair = to_py_result(crate::sphincsplus::SphincsKeyPair::generate(sphincs_variant))?;
        Ok((key_pair.public_key, key_pair.secret_key))
    }
    
    /// Sign a message using a SPHINCS+ secret key
    #[pyfunction]
    fn sphincs_sign(variant: u32, secret_key: Vec<u8>, message: Vec<u8>) -> PyResult<Vec<u8>> {
        let sphincs_variant = match variant {
            128 => crate::sphincsplus::SphincsVariant::Sphincs128f,
            129 => crate::sphincsplus::SphincsVariant::Sphincs128s,
            192 => crate::sphincsplus::SphincsVariant::Sphincs192f,
            193 => crate::sphincsplus::SphincsVariant::Sphincs192s,
            256 => crate::sphincsplus::SphincsVariant::Sphincs256f,
            257 => crate::sphincsplus::SphincsVariant::Sphincs256s,
            _ => return Err(PyValueError::new_err(format!("Invalid SPHINCS+ variant: {}", variant))),
        };
        
        let key_pair = crate::sphincsplus::SphincsKeyPair {
            public_key: Vec::new(), // Not needed for signing
            secret_key,
            algorithm: sphincs_variant,
        };
        
        to_py_result(key_pair.sign(&message))
    }
    
    /// Verify a signature using a SPHINCS+ public key
    #[pyfunction]
    fn sphincs_verify(variant: u32, public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        let sphincs_variant = match variant {
            128 => crate::sphincsplus::SphincsVariant::Sphincs128f,
            129 => crate::sphincsplus::SphincsVariant::Sphincs128s,
            192 => crate::sphincsplus::SphincsVariant::Sphincs192f,
            193 => crate::sphincsplus::SphincsVariant::Sphincs192s,
            256 => crate::sphincsplus::SphincsVariant::Sphincs256f,
            257 => crate::sphincsplus::SphincsVariant::Sphincs256s,
            _ => return Err(PyValueError::new_err(format!("Invalid SPHINCS+ variant: {}", variant))),
        };
        
        let public_key_obj = crate::sphincsplus::SphincsPublicKey {
            public_key,
            algorithm: sphincs_variant,
        };
        
        to_py_result(public_key_obj.verify(&message, &signature))
    }
    
    /// Sign a message using a SPHINCS+ secret key with compression
    #[pyfunction]
    fn sphincs_sign_compressed(variant: u32, secret_key: Vec<u8>, message: Vec<u8>, compression_level: u32) -> PyResult<Vec<u8>> {
        let sphincs_variant = match variant {
            128 => crate::sphincsplus::SphincsVariant::Sphincs128f,
            129 => crate::sphincsplus::SphincsVariant::Sphincs128s,
            192 => crate::sphincsplus::SphincsVariant::Sphincs192f,
            193 => crate::sphincsplus::SphincsVariant::Sphincs192s,
            256 => crate::sphincsplus::SphincsVariant::Sphincs256f,
            257 => crate::sphincsplus::SphincsVariant::Sphincs256s,
            _ => return Err(PyValueError::new_err(format!("Invalid SPHINCS+ variant: {}", variant))),
        };
        
        let compression = match compression_level {
            0 => crate::sphincsplus::CompressionLevel::None,
            1 => crate::sphincsplus::CompressionLevel::Light,
            2 => crate::sphincsplus::CompressionLevel::Medium,
            3 => crate::sphincsplus::CompressionLevel::High,
            _ => return Err(PyValueError::new_err(format!("Invalid compression level: {}", compression_level))),
        };
        
        let key_pair = crate::sphincsplus::SphincsKeyPair {
            public_key: Vec::new(), // Not needed for signing
            secret_key,
            algorithm: sphincs_variant,
        };
        
        let compressed_sig = to_py_result(key_pair.sign_compressed(&message, compression))?;
        Ok(compressed_sig.data().to_vec())
    }
}

// Helper function to convert an FFI result to a C return code and message
fn handle_result<T>(
    result: Result<T, CryptoError>,
    message_ptr: *mut *mut c_char,
) -> (c_int, Option<T>) {
    match result {
        Ok(value) => {
            if !message_ptr.is_null() {
                unsafe {
                    let msg = CString::new("Success").unwrap();
                    *message_ptr = msg.into_raw();
                }
            }
            (0, Some(value))
        }
        Err(err) => {
            if !message_ptr.is_null() {
                unsafe {
                    let err_msg = CString::new(err.to_string()).unwrap();
                    *message_ptr = err_msg.into_raw();
                }
            }
            (-1, None)
        }
    }
}

// Helper function to copy bytes to a pre-allocated buffer
unsafe fn copy_to_buffer(src: &[u8], dst: *mut u8, dst_size: usize) -> c_int {
    if src.len() > dst_size {
        return -1; // Buffer too small
    }

    let dst_slice = slice::from_raw_parts_mut(dst, src.len());
    dst_slice.copy_from_slice(src);

    src.len() as c_int
}

// Initialize the cryptography module
#[no_mangle]
pub extern "C" fn qasa_init(error_msg: *mut *mut c_char) -> c_int {
    let result = crate::init();
    handle_result(result, error_msg).0
}

// Free a string allocated by the library
///
/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
/// The provided pointer must be a valid pointer to memory allocated by this library
/// using the correct allocation method. If the pointer is invalid or has already
/// been freed, undefined behavior will occur.
#[no_mangle]
pub unsafe extern "C" fn qasa_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

// Free a byte buffer allocated by the library
///
/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
/// The provided pointer must be a valid pointer to memory allocated by this library
/// using the correct allocation method. If the pointer is invalid or has already
/// been freed, undefined behavior will occur.
#[no_mangle]
pub unsafe extern "C" fn qasa_free_bytes(ptr: *mut u8) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr);
    }
}

// KyberVariant helpers
fn kyber_variant_from_int(variant: c_int) -> Result<KyberVariant, CryptoError> {
    match variant {
        512 => Ok(KyberVariant::Kyber512),
        768 => Ok(KyberVariant::Kyber768),
        1024 => Ok(KyberVariant::Kyber1024),
        _ => Err(CryptoError::invalid_parameter(
            "variant",
            "512, 768, or 1024",
            &format!("{}", variant),
        )),
    }
}

// DilithiumVariant helpers
fn dilithium_variant_from_int(variant: c_int) -> Result<DilithiumVariant, CryptoError> {
    match variant {
        2 => Ok(DilithiumVariant::Dilithium2),
        3 => Ok(DilithiumVariant::Dilithium3),
        5 => Ok(DilithiumVariant::Dilithium5),
        _ => Err(CryptoError::invalid_parameter(
            "variant",
            "2, 3, or 5",
            &format!("{}", variant),
        )),
    }
}

// SPHINCS+ variant helpers
fn sphincs_variant_from_int(variant: c_int) -> Result<crate::sphincsplus::SphincsVariant, CryptoError> {
    use crate::sphincsplus::SphincsVariant;
    
    match variant {
        128 => Ok(SphincsVariant::Sphincs128f), // Fast variant
        129 => Ok(SphincsVariant::Sphincs128s), // Small variant
        192 => Ok(SphincsVariant::Sphincs192f),
        193 => Ok(SphincsVariant::Sphincs192s),
        256 => Ok(SphincsVariant::Sphincs256f),
        257 => Ok(SphincsVariant::Sphincs256s),
        _ => Err(CryptoError::invalid_parameter(
            "variant",
            "128, 129, 192, 193, 256, or 257",
            &format!("{}", variant),
        )),
    }
}

// Kyber Functions

// Generate a Kyber key pair
#[no_mangle]
pub extern "C" fn qasa_kyber_keygen(
    variant: c_int,
    public_key: *mut u8,
    public_key_size: *mut c_int,
    private_key: *mut u8,
    private_key_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let kyber_variant = match kyber_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Generate key pair
    let result = KyberKeyPair::generate(kyber_variant);
    let (status, key_pair) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let key_pair = key_pair.unwrap();

    // Copy the public key
    unsafe {
        if !public_key.is_null() && !public_key_size.is_null() {
            let max_size = *public_key_size;
            let written = copy_to_buffer(&key_pair.public_key, public_key, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "public_key_buffer",
                        &format!("{} bytes", key_pair.public_key.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *public_key_size = written;
        }

        // Copy the private key
        if !private_key.is_null() && !private_key_size.is_null() {
            let max_size = *private_key_size;
            let written = copy_to_buffer(&key_pair.secret_key, private_key, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "private_key_buffer",
                        &format!("{} bytes", key_pair.secret_key.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *private_key_size = written;
        }
    }

    0
}

// Kyber encapsulate
#[no_mangle]
pub extern "C" fn qasa_kyber_encapsulate(
    variant: c_int,
    public_key: *const u8,
    public_key_size: c_int,
    ciphertext: *mut u8,
    ciphertext_size: *mut c_int,
    shared_secret: *mut u8,
    shared_secret_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let kyber_variant = match kyber_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Create a KyberKeyPair from the provided bytes
    let public_key_bytes = unsafe {
        if public_key.is_null() || public_key_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "public_key",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(public_key, public_key_size as usize)
    };

    let key_pair = KyberKeyPair {
        public_key: public_key_bytes.to_vec(),
        secret_key: Vec::new(), // Not needed for encapsulation
        algorithm: kyber_variant,
    };

    // Encapsulate
    let result = key_pair.encapsulate();
    let (status, encap_result) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let (ct, ss) = encap_result.unwrap();

    // Copy the ciphertext
    unsafe {
        if !ciphertext.is_null() && !ciphertext_size.is_null() {
            let max_size = *ciphertext_size;
            let written = copy_to_buffer(&ct, ciphertext, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Ciphertext_buffer",
                        &format!("{} bytes", ct.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *ciphertext_size = written;
        }

        // Copy the shared secret
        if !shared_secret.is_null() && !shared_secret_size.is_null() {
            let max_size = *shared_secret_size;
            let written = copy_to_buffer(&ss, shared_secret, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Shared secret_buffer",
                        &format!("{} bytes", ss.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *shared_secret_size = written;
        }
    }

    0
}

// Kyber decapsulate
#[no_mangle]
pub extern "C" fn qasa_kyber_decapsulate(
    variant: c_int,
    private_key: *const u8,
    private_key_size: c_int,
    ciphertext: *const u8,
    ciphertext_size: c_int,
    shared_secret: *mut u8,
    shared_secret_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let kyber_variant = match kyber_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Get the private key
    let private_key_bytes = unsafe {
        if private_key.is_null() || private_key_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "private_key",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(private_key, private_key_size as usize)
    };

    // Get the ciphertext
    let ciphertext_bytes = unsafe {
        if ciphertext.is_null() || ciphertext_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "ciphertext",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(ciphertext, ciphertext_size as usize)
    };

    let key_pair = KyberKeyPair {
        public_key: Vec::new(), // Not needed for decapsulation
        secret_key: private_key_bytes.to_vec(),
        algorithm: kyber_variant,
    };

    // Decapsulate
    let result = key_pair.decapsulate(ciphertext_bytes);
    let (status, shared_secret_result) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let ss = shared_secret_result.unwrap();

    // Copy the shared secret
    unsafe {
        if !shared_secret.is_null() && !shared_secret_size.is_null() {
            let max_size = *shared_secret_size;
            let written = copy_to_buffer(&ss, shared_secret, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Shared secret_buffer",
                        &format!("{} bytes", ss.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *shared_secret_size = written;
        }
    }

    0
}

// Dilithium Functions

// Generate a Dilithium key pair
#[no_mangle]
pub extern "C" fn qasa_dilithium_keygen(
    variant: c_int,
    public_key: *mut u8,
    public_key_size: *mut c_int,
    private_key: *mut u8,
    private_key_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let dilithium_variant = match dilithium_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Generate key pair
    let result = DilithiumKeyPair::generate(dilithium_variant);
    let (status, key_pair) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let key_pair = key_pair.unwrap();

    // Copy the public key
    unsafe {
        if !public_key.is_null() && !public_key_size.is_null() {
            let max_size = *public_key_size;
            let written = copy_to_buffer(&key_pair.public_key, public_key, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Public key_buffer",
                        &format!("{} bytes", key_pair.public_key.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *public_key_size = written;
        }

        // Copy the private key
        if !private_key.is_null() && !private_key_size.is_null() {
            let max_size = *private_key_size;
            let written = copy_to_buffer(&key_pair.secret_key, private_key, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Private key_buffer",
                        &format!("{} bytes", key_pair.secret_key.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *private_key_size = written;
        }
    }

    0
}

// Dilithium sign
#[no_mangle]
pub extern "C" fn qasa_dilithium_sign(
    variant: c_int,
    private_key: *const u8,
    private_key_size: c_int,
    message: *const u8,
    message_size: c_int,
    signature: *mut u8,
    signature_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let dilithium_variant = match dilithium_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Get the private key
    let private_key_bytes = unsafe {
        if private_key.is_null() || private_key_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "private key",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(private_key, private_key_size as usize)
    };

    // Get the message
    let message_bytes = unsafe {
        if message.is_null() || message_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "message",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(message, message_size as usize)
    };

    let key_pair = DilithiumKeyPair {
        public_key: Vec::new(), // Not needed for signing
        secret_key: private_key_bytes.to_vec(),
        algorithm: dilithium_variant,
    };

    // Sign
    let result = key_pair.sign(message_bytes);
    let (status, signature_result) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let sig = signature_result.unwrap();

    // Copy the signature
    unsafe {
        if !signature.is_null() && !signature_size.is_null() {
            let max_size = *signature_size;
            let written = copy_to_buffer(&sig, signature, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Signature_buffer",
                        &format!("{} bytes", sig.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *signature_size = written;
        }
    }

    0
}

// Dilithium verify
#[no_mangle]
pub extern "C" fn qasa_dilithium_verify(
    variant: c_int,
    public_key: *const u8,
    public_key_size: c_int,
    message: *const u8,
    message_size: c_int,
    signature: *const u8,
    signature_size: c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let dilithium_variant = match dilithium_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Get the public key
    let public_key_bytes = unsafe {
        if public_key.is_null() || public_key_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "public key",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(public_key, public_key_size as usize)
    };

    // Get the message
    let message_bytes = unsafe {
        if message.is_null() || message_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "message",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(message, message_size as usize)
    };

    // Get the signature
    let signature_bytes = unsafe {
        if signature.is_null() || signature_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "signature",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(signature, signature_size as usize)
    };

    // Verify the signature
    let result = DilithiumKeyPair::verify_with_public_key(
        dilithium_variant,
        public_key_bytes,
        message_bytes,
        signature_bytes,
    );

    let (status, verify_result) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    if verify_result.unwrap() {
        1 // Valid signature
    } else {
        0 // Invalid signature
    }
}

// AES-GCM Functions

// AES-GCM encrypt
#[no_mangle]
pub extern "C" fn qasa_aes_gcm_encrypt(
    key: *const u8,
    key_size: c_int,
    plaintext: *const u8,
    plaintext_size: c_int,
    associated_data: *const u8,
    associated_data_size: c_int,
    ciphertext: *mut u8,
    ciphertext_size: *mut c_int,
    nonce: *mut u8,
    nonce_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Get the key
    let key_bytes = unsafe {
        if key.is_null() || key_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "key",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(key, key_size as usize)
    };

    // Get the plaintext
    let plaintext_bytes = unsafe {
        if plaintext.is_null() || plaintext_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "plaintext",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(plaintext, plaintext_size as usize)
    };

    // Get the associated data (can be empty)
    let aad_bytes = unsafe {
        if associated_data.is_null() {
            None
        } else {
            Some(slice::from_raw_parts(
                associated_data,
                associated_data_size as usize,
            ))
        }
    };

    // Encrypt
    let result = aes::encrypt(plaintext_bytes, key_bytes, aad_bytes);
    let (status, encrypt_result) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let (ct, nonce_bytes) = encrypt_result.unwrap();

    // Copy the ciphertext
    unsafe {
        if !ciphertext.is_null() && !ciphertext_size.is_null() {
            let max_size = *ciphertext_size;
            let written = copy_to_buffer(&ct, ciphertext, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Ciphertext_buffer",
                        &format!("{} bytes", ct.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *ciphertext_size = written;
        }

        // Copy the nonce
        if !nonce.is_null() && !nonce_size.is_null() {
            let max_size = *nonce_size;
            let written = copy_to_buffer(&nonce_bytes, nonce, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Nonce_buffer",
                        &format!("{} bytes", nonce_bytes.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *nonce_size = written;
        }
    }

    0
}

// AES-GCM decrypt
#[no_mangle]
pub extern "C" fn qasa_aes_gcm_decrypt(
    key: *const u8,
    key_size: c_int,
    ciphertext: *const u8,
    ciphertext_size: c_int,
    nonce: *const u8,
    nonce_size: c_int,
    associated_data: *const u8,
    associated_data_size: c_int,
    plaintext: *mut u8,
    plaintext_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Get the key
    let key_bytes = unsafe {
        if key.is_null() || key_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "key",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(key, key_size as usize)
    };

    // Get the ciphertext
    let ciphertext_bytes = unsafe {
        if ciphertext.is_null() || ciphertext_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "ciphertext",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(ciphertext, ciphertext_size as usize)
    };

    // Get the nonce
    let nonce_bytes = unsafe {
        if nonce.is_null() || nonce_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "nonce",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(nonce, nonce_size as usize)
    };

    // Get the associated data (can be empty)
    let aad_bytes = unsafe {
        if associated_data.is_null() {
            None
        } else {
            Some(slice::from_raw_parts(
                associated_data,
                associated_data_size as usize,
            ))
        }
    };

    // Decrypt
    let result = aes::decrypt(ciphertext_bytes, key_bytes, nonce_bytes, aad_bytes);
    let (status, plaintext_result) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let pt = plaintext_result.unwrap();

    // Copy the plaintext
    unsafe {
        if !plaintext.is_null() && !plaintext_size.is_null() {
            let max_size = *plaintext_size;
            let written = copy_to_buffer(&pt, plaintext, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Plaintext_buffer",
                        &format!("{} bytes", pt.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *plaintext_size = written;
        }
    }

    0
}

// SPHINCS+ Functions

// Generate a SPHINCS+ key pair
#[no_mangle]
pub extern "C" fn qasa_sphincs_keygen(
    variant: c_int,
    public_key: *mut u8,
    public_key_size: *mut c_int,
    private_key: *mut u8,
    private_key_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let sphincs_variant = match sphincs_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Generate key pair
    let result = crate::sphincsplus::SphincsKeyPair::generate(sphincs_variant);
    let (status, key_pair) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let key_pair = key_pair.unwrap();

    // Copy the public key
    unsafe {
        if !public_key.is_null() && !public_key_size.is_null() {
            let max_size = *public_key_size;
            let written = copy_to_buffer(&key_pair.public_key, public_key, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "public_key_buffer",
                        &format!("{} bytes", key_pair.public_key.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *public_key_size = written;
        }

        // Copy the private key
        if !private_key.is_null() && !private_key_size.is_null() {
            let max_size = *private_key_size;
            let written = copy_to_buffer(&key_pair.secret_key, private_key, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "private_key_buffer",
                        &format!("{} bytes", key_pair.secret_key.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *private_key_size = written;
        }
    }

    0
}

// SPHINCS+ sign
#[no_mangle]
pub extern "C" fn qasa_sphincs_sign(
    variant: c_int,
    private_key: *const u8,
    private_key_size: c_int,
    message: *const u8,
    message_size: c_int,
    signature: *mut u8,
    signature_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let sphincs_variant = match sphincs_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Get the private key
    let private_key_bytes = unsafe {
        if private_key.is_null() || private_key_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "private key",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(private_key, private_key_size as usize)
    };

    // Get the message
    let message_bytes = unsafe {
        if message.is_null() || message_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "message",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(message, message_size as usize)
    };

    let key_pair = crate::sphincsplus::SphincsKeyPair {
        public_key: Vec::new(), // Not needed for signing
        secret_key: private_key_bytes.to_vec(),
        algorithm: sphincs_variant,
    };

    // Sign
    let result = key_pair.sign(message_bytes);
    let (status, signature_result) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let sig = signature_result.unwrap();

    // Copy the signature
    unsafe {
        if !signature.is_null() && !signature_size.is_null() {
            let max_size = *signature_size;
            let written = copy_to_buffer(&sig, signature, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Signature_buffer",
                        &format!("{} bytes", sig.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *signature_size = written;
        }
    }

    0
}

// SPHINCS+ verify
#[no_mangle]
pub extern "C" fn qasa_sphincs_verify(
    variant: c_int,
    public_key: *const u8,
    public_key_size: c_int,
    message: *const u8,
    message_size: c_int,
    signature: *const u8,
    signature_size: c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let sphincs_variant = match sphincs_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Get the public key
    let public_key_bytes = unsafe {
        if public_key.is_null() || public_key_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "public key",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(public_key, public_key_size as usize)
    };

    // Get the message
    let message_bytes = unsafe {
        if message.is_null() || message_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "message",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(message, message_size as usize)
    };

    // Get the signature
    let signature_bytes = unsafe {
        if signature.is_null() || signature_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "signature",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(signature, signature_size as usize)
    };

    // Create a public key object
    let public_key_obj = crate::sphincsplus::SphincsPublicKey {
        public_key: public_key_bytes.to_vec(),
        algorithm: sphincs_variant,
    };

    // Verify the signature
    let result = public_key_obj.verify(message_bytes, signature_bytes);
    let (status, verify_result) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    if verify_result.unwrap() {
        1 // Valid signature
    } else {
        0 // Invalid signature
    }
}

// SPHINCS+ sign with compression
#[no_mangle]
pub extern "C" fn qasa_sphincs_sign_compressed(
    variant: c_int,
    private_key: *const u8,
    private_key_size: c_int,
    message: *const u8,
    message_size: c_int,
    compression_level: c_int,
    signature: *mut u8,
    signature_size: *mut c_int,
    error_msg: *mut *mut c_char,
) -> c_int {
    // Convert the variant
    let sphincs_variant = match sphincs_variant_from_int(variant) {
        Ok(v) => v,
        Err(e) => {
            handle_result::<()>(Err(e), error_msg);
            return -1;
        }
    };

    // Convert compression level
    let compression = match compression_level {
        0 => crate::sphincsplus::CompressionLevel::None,
        1 => crate::sphincsplus::CompressionLevel::Light,
        2 => crate::sphincsplus::CompressionLevel::Medium,
        3 => crate::sphincsplus::CompressionLevel::High,
        _ => {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "compression_level",
                    "0 (None), 1 (Light), 2 (Medium), or 3 (High)",
                    &format!("{}", compression_level),
                )),
                error_msg,
            );
            return -1;
        }
    };

    // Get the private key
    let private_key_bytes = unsafe {
        if private_key.is_null() || private_key_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "private key",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(private_key, private_key_size as usize)
    };

    // Get the message
    let message_bytes = unsafe {
        if message.is_null() || message_size <= 0 {
            handle_result::<()>(
                Err(CryptoError::invalid_parameter(
                    "message",
                    "valid non-null pointer",
                    "null or invalid",
                )),
                error_msg,
            );
            return -1;
        }
        slice::from_raw_parts(message, message_size as usize)
    };

    let key_pair = crate::sphincsplus::SphincsKeyPair {
        public_key: Vec::new(), // Not needed for signing
        secret_key: private_key_bytes.to_vec(),
        algorithm: sphincs_variant,
    };

    // Sign with compression
    let result = key_pair.sign_compressed(message_bytes, compression);
    let (status, compressed_sig) = handle_result(result, error_msg);

    if status != 0 {
        return status;
    }

    let compressed_sig = compressed_sig.unwrap();
    let sig_data = compressed_sig.data();

    // Copy the signature
    unsafe {
        if !signature.is_null() && !signature_size.is_null() {
            let max_size = *signature_size;
            let written = copy_to_buffer(sig_data, signature, max_size as usize);
            if written < 0 {
                handle_result::<()>(
                    Err(CryptoError::invalid_parameter(
                        "Signature_buffer",
                        &format!("{} bytes", sig_data.len()),
                        &format!("{} bytes", max_size),
                    )),
                    error_msg,
                );
                return -1;
            }
            *signature_size = written;
        }
    }

    0
}
