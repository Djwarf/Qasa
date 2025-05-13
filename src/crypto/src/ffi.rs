use std::ffi::{c_char, c_int, CString};
use std::slice;

use crate::aes;
use crate::dilithium::{DilithiumKeyPair, DilithiumVariant};
use crate::error::CryptoError;
use crate::kyber::{KyberKeyPair, KyberVariant};

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
pub extern "C" fn qasa_crypto_init(error_msg: *mut *mut c_char) -> c_int {
    let result = crate::init();
    handle_result(result, error_msg).0
}

// Free a string allocated by the library
#[no_mangle]
pub extern "C" fn qasa_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// Free a byte buffer allocated by the library
#[no_mangle]
pub extern "C" fn qasa_free_bytes(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

// KyberVariant helpers
fn kyber_variant_from_int(variant: c_int) -> Result<KyberVariant, CryptoError> {
    match variant {
        512 => Ok(KyberVariant::Kyber512),
        768 => Ok(KyberVariant::Kyber768),
        1024 => Ok(KyberVariant::Kyber1024),
        _ => Err(CryptoError::InvalidParameterError(format!(
            "Invalid Kyber variant: {}. Expected 512, 768, or 1024.",
            variant
        ))),
    }
}

// DilithiumVariant helpers
fn dilithium_variant_from_int(variant: c_int) -> Result<DilithiumVariant, CryptoError> {
    match variant {
        2 => Ok(DilithiumVariant::Dilithium2),
        3 => Ok(DilithiumVariant::Dilithium3),
        5 => Ok(DilithiumVariant::Dilithium5),
        _ => Err(CryptoError::InvalidParameterError(format!(
            "Invalid Dilithium variant: {}. Expected 2, 3, or 5.",
            variant
        ))),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Public key buffer too small. Required: {}, provided: {}",
                        key_pair.public_key.len(),
                        max_size
                    ))),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Private key buffer too small. Required: {}, provided: {}",
                        key_pair.secret_key.len(),
                        max_size
                    ))),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid public key".to_string(),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Ciphertext buffer too small. Required: {}, provided: {}",
                        ct.len(),
                        max_size
                    ))),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Shared secret buffer too small. Required: {}, provided: {}",
                        ss.len(),
                        max_size
                    ))),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid private key".to_string(),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid ciphertext".to_string(),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Shared secret buffer too small. Required: {}, provided: {}",
                        ss.len(),
                        max_size
                    ))),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Public key buffer too small. Required: {}, provided: {}",
                        key_pair.public_key.len(),
                        max_size
                    ))),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Private key buffer too small. Required: {}, provided: {}",
                        key_pair.secret_key.len(),
                        max_size
                    ))),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid private key".to_string(),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid message".to_string(),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Signature buffer too small. Required: {}, provided: {}",
                        sig.len(),
                        max_size
                    ))),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid public key".to_string(),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid message".to_string(),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid signature".to_string(),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid key".to_string(),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid plaintext".to_string(),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Ciphertext buffer too small. Required: {}, provided: {}",
                        ct.len(),
                        max_size
                    ))),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Nonce buffer too small. Required: {}, provided: {}",
                        nonce_bytes.len(),
                        max_size
                    ))),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid key".to_string(),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid ciphertext".to_string(),
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
                Err(CryptoError::InvalidParameterError(
                    "Invalid nonce".to_string(),
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
                    Err(CryptoError::InvalidParameterError(format!(
                        "Plaintext buffer too small. Required: {}, provided: {}",
                        pt.len(),
                        max_size
                    ))),
                    error_msg,
                );
                return -1;
            }
            *plaintext_size = written;
        }
    }

    0
}
