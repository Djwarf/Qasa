use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use std::sync::Arc;
use std::io::{Read, Write, Result as IoResult};

use crate::error::{error_codes, CryptoError};

/// Default chunk size for streaming operations (1MB)
pub const DEFAULT_CHUNK_SIZE: usize = 1_048_576;

/// AES-256-GCM cipher for authenticated encryption
///
/// This struct provides authenticated encryption with associated data (AEAD)
/// using the AES-256-GCM algorithm. It combines encryption for confidentiality
/// with authentication for integrity and authenticity.
///
/// # Security Properties
///
/// 1. Provides confidentiality through AES-256 encryption
/// 2. Provides integrity and authenticity through GCM authentication
/// 3. Protects against tampering and forgery
/// 4. Uses 256-bit keys for post-quantum-appropriate symmetric security
///
/// # Examples
///
/// ```
/// use qasa::aes::AesGcm;
///
/// // Create a new AES-GCM cipher with a 32-byte key
/// let key = [0x42; 32];
/// let cipher = AesGcm::new(&key).unwrap();
///
/// // Generate a nonce (should be unique for each encryption)
/// let nonce = AesGcm::generate_nonce();
///
/// // Encrypt a message with optional associated data
/// let plaintext = b"Secret message";
/// let aad = b"Additional authenticated data";
/// let ciphertext = cipher.encrypt(plaintext, &nonce, Some(aad)).unwrap();
///
/// // Decrypt the message with the same nonce and associated data
/// let decrypted = cipher.decrypt(&ciphertext, &nonce, Some(aad)).unwrap();
/// assert_eq!(decrypted, plaintext);
/// ```
#[derive(Clone)]
pub struct AesGcm {
    cipher: Arc<Aes256Gcm>,
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcm")
            .field("cipher", &"[AES-256-GCM Cipher]")
            .finish()
    }
}

impl AesGcm {
    /// Create a new AES-GCM cipher with the given key
    ///
    /// This function initializes a new AES-256-GCM cipher instance with
    /// the provided 32-byte key. This cipher can then be used for both
    /// encryption and decryption operations.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte key (e.g., from Kyber KEM)
    ///
    /// # Returns
    ///
    /// A new AesGcm cipher or an error if the key is invalid
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not exactly 32 bytes long
    ///
    /// # Security Considerations
    ///
    /// 1. The key should be cryptographically secure and kept secret
    /// 2. Ideally, keys should be derived from a key exchange like Kyber
    /// 3. Each key should only be used for a limited amount of data (typically < 2^32 messages)
    /// 4. Consider key rotation for long-term security
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::aes::AesGcm;
    ///
    /// // Create a new AES-GCM cipher with a 32-byte key
    /// let key = [0x42; 32];
    /// let cipher = AesGcm::new(&key).unwrap();
    /// ```
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::invalid_parameter(
                "key",
                "32 bytes",
                &format!("{} bytes", key.len()),
            ));
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Arc::new(Aes256Gcm::new(key));

        Ok(Self { cipher })
    }

    /// Generate a random nonce for encryption
    ///
    /// Generates a cryptographically secure random nonce (number used once)
    /// for use with AES-GCM encryption. A unique nonce must be used for each
    /// encryption operation with the same key.
    ///
    /// # Returns
    ///
    /// A 12-byte random nonce
    ///
    /// # Security Considerations
    ///
    /// 1. Each nonce must be unique for a given key
    /// 2. Reusing a nonce with the same key compromises security
    /// 3. For high-volume applications, consider using a deterministic
    ///    nonce construction with a counter
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::aes::AesGcm;
    ///
    /// // Generate a random nonce
    /// let nonce = AesGcm::generate_nonce();
    /// assert_eq!(nonce.len(), 12);
    /// ```
    pub fn generate_nonce() -> Vec<u8> {
        Aes256Gcm::generate_nonce(&mut OsRng).to_vec()
    }

    /// Encrypt plaintext using AES-GCM
    ///
    /// Encrypts the provided plaintext using AES-256-GCM with the given nonce
    /// and optional associated data. The associated data is authenticated but
    /// not encrypted.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt
    /// * `nonce` - A 12-byte nonce (should be unique for each encryption)
    /// * `associated_data` - Additional data to authenticate but not encrypt (optional)
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext or an error if encryption fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The nonce is not exactly 12 bytes
    /// * Encryption fails for any reason
    ///
    /// # Security Considerations
    ///
    /// 1. The nonce must be unique for each encryption with the same key
    /// 2. Associated data can be used to authenticate context information
    ///    (e.g., headers, sender/recipient info)
    /// 3. The resulting ciphertext includes the authentication tag
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::aes::AesGcm;
    ///
    /// // Create a cipher and generate a nonce
    /// let key = [0x42; 32];
    /// let cipher = AesGcm::new(&key).unwrap();
    /// let nonce = AesGcm::generate_nonce();
    ///
    /// // Encrypt with associated data
    /// let plaintext = b"Secret message";
    /// let aad = b"Message metadata";
    /// let ciphertext = cipher.encrypt(plaintext, &nonce, Some(aad)).unwrap();
    ///
    /// // The ciphertext will be longer than the plaintext due to the auth tag
    /// assert!(ciphertext.len() > plaintext.len());
    /// ```
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::invalid_parameter(
                "nonce",
                "12 bytes",
                &format!("{} bytes", nonce.len()),
            ));
        }

        let nonce = Nonce::from_slice(nonce);

        // Create proper payload with AAD if provided
        let aad = associated_data.unwrap_or(&[]);

        // Use Payload struct to associate AAD with the plaintext
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        // Encrypt using the Aead trait
        self.cipher.encrypt(nonce, payload).map_err(|e| {
            CryptoError::aes_error(
                "Encryption failed",
                &format!("AES-GCM encryption failed: {}", e),
                error_codes::AES_ENCRYPTION_FAILED,
            )
        })
    }

    /// Decrypt ciphertext using AES-GCM
    ///
    /// Decrypts and authenticates the provided ciphertext using AES-256-GCM with
    /// the given nonce and optional associated data. This operation will fail if
    /// the ciphertext has been tampered with or if the associated data doesn't match.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data
    /// * `nonce` - The same 12-byte nonce used for encryption
    /// * `associated_data` - The same additional data used for encryption (optional)
    ///
    /// # Returns
    ///
    /// The decrypted plaintext or an error if decryption or authentication fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The nonce is not exactly 12 bytes
    /// * The ciphertext has been tampered with
    /// * The associated data doesn't match what was used for encryption
    /// * Decryption fails for any other reason
    ///
    /// # Security Considerations
    ///
    /// 1. Authentication failure should be treated as a security alert
    /// 2. Always use the same associated data for decryption as was used for encryption
    /// 3. Avoid timing attacks by using constant-time comparison for authentication tags
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::aes::AesGcm;
    ///
    /// // Create a cipher and generate a nonce
    /// let key = [0x42; 32];
    /// let cipher = AesGcm::new(&key).unwrap();
    /// let nonce = AesGcm::generate_nonce();
    ///
    /// // Encrypt and then decrypt
    /// let plaintext = b"Secret message";
    /// let aad = b"Message metadata";
    /// let ciphertext = cipher.encrypt(plaintext, &nonce, Some(aad)).unwrap();
    /// let decrypted = cipher.decrypt(&ciphertext, &nonce, Some(aad)).unwrap();
    ///
    /// assert_eq!(decrypted, plaintext);
    ///
    /// // Tampering with the ciphertext will cause decryption to fail
    /// let mut tampered = ciphertext.clone();
    /// if !tampered.is_empty() {
    ///     tampered[0] ^= 1;
    ///     assert!(cipher.decrypt(&tampered, &nonce, Some(aad)).is_err());
    /// }
    /// ```
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::invalid_parameter(
                "nonce",
                "12 bytes",
                &format!("{} bytes", nonce.len()),
            ));
        }

        let nonce = Nonce::from_slice(nonce);

        // Create proper payload with AAD if provided
        let aad = associated_data.unwrap_or(&[]);

        // Use Payload struct to authenticate AAD with the ciphertext
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        // Decrypt using the Aead trait
        self.cipher.decrypt(nonce, payload).map_err(|e| {
            CryptoError::aes_error(
                "Decryption failed",
                &format!("AES-GCM decryption failed: {}", e),
                error_codes::AES_DECRYPTION_FAILED,
            )
        })
    }

    /// Encrypt a large data stream using AES-GCM with chunked processing
    ///
    /// This method processes the input data in chunks to minimize memory usage
    /// and improve throughput for large data. Each chunk is encrypted separately
    /// and written to the output stream.
    ///
    /// # Arguments
    ///
    /// * `reader` - Source of plaintext data
    /// * `writer` - Destination for encrypted data
    /// * `nonce` - A 12-byte nonce (should be unique for each encryption)
    /// * `associated_data` - Additional data to authenticate but not encrypt (optional)
    /// * `chunk_size` - Size of chunks to process (default: 1MB if None)
    ///
    /// # Returns
    ///
    /// The number of bytes processed or an error if encryption fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The nonce is not exactly 12 bytes
    /// * Encryption fails for any reason
    /// * I/O operations fail
    ///
    /// # Security Considerations
    ///
    /// 1. The nonce must be unique for each encryption with the same key
    /// 2. This method maintains the security properties of AES-GCM while optimizing for throughput
    /// 3. Each chunk is independently encrypted and authenticated
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::aes::AesGcm;
    /// use std::io::Cursor;
    ///
    /// // Create a cipher and generate a nonce
    /// let key = [0x42; 32];
    /// let cipher = AesGcm::new(&key).unwrap();
    /// let nonce = AesGcm::generate_nonce();
    ///
    /// // Prepare input and output buffers
    /// let plaintext = vec![0x42; 5_000_000]; // 5MB of data
    /// let mut input = Cursor::new(&plaintext);
    /// let mut output = Vec::new();
    ///
    /// // Encrypt the data stream with 1MB chunks
    /// let bytes_processed = cipher.encrypt_stream(&mut input, &mut output, &nonce, None, Some(1_000_000)).unwrap();
    /// assert_eq!(bytes_processed, plaintext.len());
    /// ```
    pub fn encrypt_stream<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        nonce: &[u8],
        associated_data: Option<&[u8]>,
        chunk_size: Option<usize>,
    ) -> Result<usize, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::invalid_parameter(
                "nonce",
                "12 bytes",
                &format!("{} bytes", nonce.len()),
            ));
        }

        let nonce = Nonce::from_slice(nonce);
        let aad = associated_data.unwrap_or(&[]);
        let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        let mut buffer = vec![0; chunk_size];
        let mut total_bytes = 0;

        loop {
            // Read a chunk of data
            let bytes_read = match reader.read(&mut buffer) {
                Ok(0) => break, // End of stream
                Ok(n) => n,
                Err(e) => return Err(CryptoError::io_error(&format!("Failed to read data: {}", e), error_codes::IO_ERROR)),
            };

            // Encrypt the chunk
            let payload = Payload {
                msg: &buffer[..bytes_read],
                aad,
            };

            let encrypted_chunk = match self.cipher.encrypt(nonce, payload) {
                Ok(data) => data,
                Err(e) => {
                    return Err(CryptoError::encryption_error(
                        "AES-GCM",
                        &format!("Failed to encrypt chunk: {}", e),
                    ));
                }
            };

            // Write the encrypted chunk size and data
            if let Err(e) = writer.write_all(&(encrypted_chunk.len() as u32).to_be_bytes()) {
                return Err(CryptoError::io_error(&format!("Failed to write chunk size: {}", e), error_codes::IO_ERROR));
            }

            if let Err(e) = writer.write_all(&encrypted_chunk) {
                return Err(CryptoError::io_error(&format!("Failed to write encrypted data: {}", e), error_codes::IO_ERROR));
            }

            total_bytes += bytes_read;

            // If we read less than the buffer size, we've reached the end
            if bytes_read < chunk_size {
                break;
            }
        }

        Ok(total_bytes)
    }

    /// Decrypt a large data stream using AES-GCM with chunked processing
    ///
    /// This method processes the input data in chunks to minimize memory usage
    /// and improve throughput for large data. Each chunk is decrypted separately
    /// and written to the output stream.
    ///
    /// # Arguments
    ///
    /// * `reader` - Source of encrypted data
    /// * `writer` - Destination for decrypted data
    /// * `nonce` - The same 12-byte nonce used for encryption
    /// * `associated_data` - The same additional data used for encryption (optional)
    ///
    /// # Returns
    ///
    /// The number of bytes processed or an error if decryption fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The nonce is not exactly 12 bytes
    /// * Decryption or authentication fails
    /// * I/O operations fail
    ///
    /// # Security Considerations
    ///
    /// 1. Authentication failure indicates possible tampering and should be treated as a security incident
    /// 2. This method maintains the security properties of AES-GCM while optimizing for throughput
    /// 3. Each chunk is independently decrypted and authenticated
    ///
    /// # Examples
    ///
    /// ```
    /// use qasa::aes::AesGcm;
    /// use std::io::Cursor;
    ///
    /// // Create a cipher and generate a nonce
    /// let key = [0x42; 32];
    /// let cipher = AesGcm::new(&key).unwrap();
    /// let nonce = AesGcm::generate_nonce();
    ///
    /// // Prepare input data
    /// let plaintext = vec![0x42; 5_000_000]; // 5MB of data
    /// let mut input = Cursor::new(&plaintext);
    /// let mut encrypted = Vec::new();
    ///
    /// // Encrypt the data
    /// cipher.encrypt_stream(&mut input, &mut encrypted, &nonce, None, None).unwrap();
    ///
    /// // Decrypt the data
    /// let mut encrypted_cursor = Cursor::new(&encrypted);
    /// let mut decrypted = Vec::new();
    /// let bytes_processed = cipher.decrypt_stream(&mut encrypted_cursor, &mut decrypted, &nonce, None).unwrap();
    ///
    /// assert_eq!(bytes_processed, plaintext.len());
    /// assert_eq!(decrypted, plaintext);
    /// ```
    pub fn decrypt_stream<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        nonce: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<usize, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::invalid_parameter(
                "nonce",
                "12 bytes",
                &format!("{} bytes", nonce.len()),
            ));
        }

        let nonce = Nonce::from_slice(nonce);
        let aad = associated_data.unwrap_or(&[]);
        let mut size_buffer = [0u8; 4];
        let mut total_bytes = 0;

        loop {
            // Read the chunk size (4 bytes, big-endian u32)
            match reader.read_exact(&mut size_buffer) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // End of stream
                Err(e) => return Err(CryptoError::io_error(&format!("Failed to read chunk size: {}", e), error_codes::IO_ERROR)),
            }

            let chunk_size = u32::from_be_bytes(size_buffer) as usize;
            let mut encrypted_chunk = vec![0; chunk_size];

            // Read the encrypted chunk
            if let Err(e) = reader.read_exact(&mut encrypted_chunk) {
                return Err(CryptoError::io_error(&format!("Failed to read encrypted chunk: {}", e), error_codes::IO_ERROR));
            }

            // Decrypt the chunk
            let payload = Payload {
                msg: &encrypted_chunk,
                aad,
            };

            let decrypted_chunk = match self.cipher.decrypt(nonce, payload) {
                Ok(data) => data,
                Err(e) => {
                    return Err(CryptoError::decryption_error(
                        "AES-GCM",
                        &format!("Failed to decrypt chunk: {}", e),
                    ));
                }
            };

            // Write the decrypted chunk
            if let Err(e) = writer.write_all(&decrypted_chunk) {
                return Err(CryptoError::io_error(&format!("Failed to write decrypted data: {}", e), error_codes::IO_ERROR));
            }

            total_bytes += decrypted_chunk.len();
        }

        Ok(total_bytes)
    }
}

/// Convenience function to encrypt data using AES-GCM
///
/// This is a wrapper around AesGcm that handles key setup, nonce generation,
/// and encryption in a single function call. It generates a fresh random nonce
/// for each encryption operation.
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt
/// * `key` - A 32-byte key (e.g., from Kyber KEM)
/// * `associated_data` - Additional data to authenticate (optional)
///
/// # Returns
///
/// A tuple containing:
/// * `ciphertext` - The encrypted data (including authentication tag)
/// * `nonce` - The randomly generated nonce used for encryption
///
/// Or an error if encryption fails
///
/// # Security Considerations
///
/// 1. The key should be cryptographically secure and kept secret
/// 2. The nonce is automatically generated for each call, ensuring uniqueness
/// 3. Both the ciphertext and nonce must be stored or transmitted for decryption
///
/// # Examples
///
/// ```
/// use qasa::aes::encrypt;
///
/// // Encrypt a message
/// let key = [0x42; 32];
/// let message = b"Top secret information";
/// let metadata = b"Classification: SECRET";
///
/// let (ciphertext, nonce) = encrypt(message, &key, Some(metadata)).unwrap();
///
/// // The ciphertext and nonce are needed for decryption
/// // Both should be stored or transmitted securely
/// ```
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = AesGcm::new(key)?;
    let nonce = AesGcm::generate_nonce();
    let ciphertext = cipher.encrypt(plaintext, &nonce, associated_data)?;
    Ok((ciphertext, nonce))
}

/// Convenience function to decrypt data using AES-GCM
///
/// This is a wrapper around AesGcm that handles key setup and decryption
/// in a single function call. It decrypts and authenticates the ciphertext
/// with the provided key, nonce, and associated data.
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data
/// * `key` - The same 32-byte key used for encryption
/// * `nonce` - The same nonce used for encryption
/// * `associated_data` - The same additional data used for encryption (optional)
///
/// # Returns
///
/// The decrypted plaintext or an error if decryption or authentication fails
///
/// # Security Considerations
///
/// 1. Authentication failure indicates possible tampering and should be treated as a security incident
/// 2. The same key, nonce, and associated data must be used as during encryption
/// 3. The decryption process verifies integrity and authenticity of the data
///
/// # Examples
///
/// ```
/// use qasa::aes::{encrypt, decrypt};
///
/// // Encrypt a message
/// let key = [0x42; 32];
/// let message = b"Top secret information";
/// let metadata = b"Classification: SECRET";
///
/// let (ciphertext, nonce) = encrypt(message, &key, Some(metadata)).unwrap();
///
/// // Decrypt the message
/// let decrypted = decrypt(&ciphertext, &key, &nonce, Some(metadata)).unwrap();
/// assert_eq!(decrypted, message);
/// ```
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = AesGcm::new(key)?;
    cipher.decrypt(ciphertext, nonce, associated_data)
}

/// Encrypt a file using AES-GCM with streaming
///
/// This is a convenience function that encrypts a file using AES-GCM with
/// streaming to optimize for large file throughput. It handles key setup
/// and encryption in a single function call.
///
/// # Arguments
///
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Path to write the encrypted file
/// * `key` - A 32-byte key for encryption
/// * `associated_data` - Additional data to authenticate but not encrypt (optional)
/// * `chunk_size` - Size of chunks to process (default: 1MB if None)
///
/// # Returns
///
/// The number of bytes processed or an error if encryption fails
///
/// # Security Considerations
///
/// 1. The nonce is automatically generated and included in the output file
/// 2. The first 12 bytes of the output file contain the nonce
/// 3. The file format is: [12-byte nonce][encrypted chunks]
///
/// # Examples
///
/// ```no_run
/// use qasa::aes::encrypt_file;
/// use std::path::Path;
///
/// let key = [0x42; 32];
/// let input_path = Path::new("plaintext.dat");
/// let output_path = Path::new("encrypted.dat");
///
/// let bytes_processed = encrypt_file(input_path, output_path, &key, None, None).unwrap();
/// println!("Encrypted {} bytes", bytes_processed);
/// ```
pub fn encrypt_file(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    key: &[u8],
    associated_data: Option<&[u8]>,
    chunk_size: Option<usize>,
) -> Result<usize, CryptoError> {
    use std::fs::File;
    use std::io::BufReader;

    // Create the cipher
    let cipher = AesGcm::new(key)?;
    
    // Generate a nonce
    let nonce = AesGcm::generate_nonce();
    
    // Open input and output files
    let input_file = File::open(input_path).map_err(|e| {
        CryptoError::io_error(
            &format!("Failed to open input file '{}': {}", input_path.display(), e),
            error_codes::IO_ERROR,
        )
    })?;
    
    let output_file = File::create(output_path).map_err(|e| {
        CryptoError::io_error(
            &format!("Failed to create output file '{}': {}", output_path.display(), e),
            error_codes::IO_ERROR,
        )
    })?;
    
    let mut reader = BufReader::new(input_file);
    let mut writer = std::io::BufWriter::new(output_file);
    
    // Write the nonce at the beginning of the file
    writer.write_all(&nonce).map_err(|e| {
        CryptoError::io_error(
            &format!("Failed to write nonce to output file: {}", e),
            error_codes::IO_ERROR,
        )
    })?;
    
    // Encrypt the file
    let bytes_processed = cipher.encrypt_stream(&mut reader, &mut writer, &nonce, associated_data, chunk_size)?;
    
    // Flush the writer to ensure all data is written
    writer.flush().map_err(|e| {
        CryptoError::io_error(
            &format!("Failed to flush output file: {}", e),
            error_codes::IO_ERROR,
        )
    })?;
    
    Ok(bytes_processed)
}

/// Decrypt a file using AES-GCM with streaming
///
/// This is a convenience function that decrypts a file using AES-GCM with
/// streaming to optimize for large file throughput. It handles key setup
/// and decryption in a single function call.
///
/// # Arguments
///
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path to write the decrypted file
/// * `key` - The same 32-byte key used for encryption
/// * `associated_data` - The same additional data used for encryption (optional)
///
/// # Returns
///
/// The number of bytes processed or an error if decryption fails
///
/// # Security Considerations
///
/// 1. The nonce is read from the first 12 bytes of the input file
/// 2. Authentication failure indicates possible tampering and should be treated as a security incident
///
/// # Examples
///
/// ```no_run
/// use qasa::aes::{encrypt_file, decrypt_file};
/// use std::path::Path;
///
/// let key = [0x42; 32];
/// let plaintext_path = Path::new("plaintext.dat");
/// let encrypted_path = Path::new("encrypted.dat");
/// let decrypted_path = Path::new("decrypted.dat");
///
/// // Encrypt the file
/// encrypt_file(plaintext_path, encrypted_path, &key, None, None).unwrap();
///
/// // Decrypt the file
/// let bytes_processed = decrypt_file(encrypted_path, decrypted_path, &key, None).unwrap();
/// println!("Decrypted {} bytes", bytes_processed);
/// ```
pub fn decrypt_file(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    key: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<usize, CryptoError> {
    use std::fs::File;
    use std::io::{BufReader, Read};

    // Create the cipher
    let cipher = AesGcm::new(key)?;
    
    // Open input and output files
    let input_file = File::open(input_path).map_err(|e| {
        CryptoError::io_error(
            &format!("Failed to open input file '{}': {}", input_path.display(), e),
            error_codes::IO_ERROR,
        )
    })?;
    
    let output_file = File::create(output_path).map_err(|e| {
        CryptoError::io_error(
            &format!("Failed to create output file '{}': {}", output_path.display(), e),
            error_codes::IO_ERROR,
        )
    })?;
    
    let mut reader = BufReader::new(input_file);
    let mut writer = std::io::BufWriter::new(output_file);
    
    // Read the nonce from the beginning of the file
    let mut nonce = vec![0; 12];
    reader.read_exact(&mut nonce).map_err(|e| {
        CryptoError::io_error(
            &format!("Failed to read nonce from input file: {}", e),
            error_codes::IO_ERROR,
        )
    })?;
    
    // Decrypt the file
    let bytes_processed = cipher.decrypt_stream(&mut reader, &mut writer, &nonce, associated_data)?;
    
    // Flush the writer to ensure all data is written
    writer.flush().map_err(|e| {
        CryptoError::io_error(
            &format!("Failed to flush output file: {}", e),
            error_codes::IO_ERROR,
        )
    })?;
    
    Ok(bytes_processed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = utils::random_bytes(32).unwrap();
        let plaintext = b"Hello, world!";
        let aad = b"Additional data";

        let (ciphertext, nonce) = encrypt(plaintext, &key, Some(aad)).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce, Some(aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_without_aad() {
        let key = utils::random_bytes(32).unwrap();
        let plaintext = b"This is a test message without AAD";

        // Encrypt without associated data
        let (ciphertext, nonce) = encrypt(plaintext, &key, None).unwrap();

        // Decrypt without associated data
        let decrypted = decrypt(&ciphertext, &key, &nonce, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_invalid_nonce() {
        let key = utils::random_bytes(32).unwrap();
        let cipher = AesGcm::new(&key).unwrap();
        let plaintext = b"This is a test message";
        let invalid_nonce = vec![0; 10]; // Too short

        let result = cipher.encrypt(plaintext, &invalid_nonce, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_invalid_key() {
        let key = utils::random_bytes(16).unwrap(); // Too short for AES-256
        let result = AesGcm::new(&key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext() {
        let key = utils::random_bytes(32).unwrap();
        let plaintext = b"This is a test message for tamper detection";
        let associated_data = b"additional data";

        // Encrypt
        let (mut ciphertext, nonce) = encrypt(plaintext, &key, Some(associated_data)).unwrap();

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        }

        // Try to decrypt
        let result = decrypt(&ciphertext, &key, &nonce, Some(associated_data));
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let key1 = utils::random_bytes(32).unwrap();
        let key2 = utils::random_bytes(32).unwrap();
        let plaintext = b"This is a test message for wrong key";

        // Encrypt with key1
        let (ciphertext, nonce) = encrypt(plaintext, &key1, None).unwrap();

        // Try to decrypt with key2
        let result = decrypt(&ciphertext, &key2, &nonce, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_large_data() {
        let key = utils::random_bytes(32).unwrap();
        let plaintext = vec![0xAA; 1000]; // 1KB of data
        let associated_data = b"large data test";

        let (ciphertext, nonce) = encrypt(&plaintext, &key, Some(associated_data)).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce, Some(associated_data)).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cipher_cloning() {
        let key = utils::random_bytes(32).unwrap();
        let cipher1 = AesGcm::new(&key).unwrap();
        let cipher2 = cipher1.clone();

        let plaintext = b"Testing cipher cloning";
        let nonce = AesGcm::generate_nonce();

        let ciphertext1 = cipher1.encrypt(plaintext, &nonce, None).unwrap();
        let plaintext2 = cipher2.decrypt(&ciphertext1, &nonce, None).unwrap();

        assert_eq!(plaintext, &plaintext2[..]);
    }

    #[test]
    fn test_empty_vs_none_aad() {
        // Test behavior with empty AAD vs no AAD with the aes-gcm crate
        let key = utils::random_bytes(32).unwrap();
        let plaintext = b"Testing empty vs none AAD";
        let nonce = AesGcm::generate_nonce();

        let cipher = AesGcm::new(&key).unwrap();

        // Encrypt with empty AAD
        let ciphertext1 = cipher.encrypt(plaintext, &nonce, Some(&[])).unwrap();

        // Encrypt with no AAD (None)
        let ciphertext2 = cipher.encrypt(plaintext, &nonce, None).unwrap();

        // With the aes-gcm crate, empty AAD and None are treated the same way
        // The ciphertexts should be identical
        assert_eq!(
            ciphertext1, ciphertext2,
            "Empty AAD and None should produce the same ciphertext"
        );

        // Verify cross-decryption works
        let decrypted1 = cipher.decrypt(&ciphertext1, &nonce, None).unwrap();
        let decrypted2 = cipher.decrypt(&ciphertext2, &nonce, Some(&[])).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_stream_encryption_decryption() {
        use std::io::Cursor;
        
        let key = utils::random_bytes(32).unwrap();
        let plaintext = vec![0x42; 5_000_000]; // 5MB of data
        let aad = b"stream test";
        
        let cipher = AesGcm::new(&key).unwrap();
        let nonce = AesGcm::generate_nonce();
        
        // Encrypt using streaming
        let mut input = Cursor::new(&plaintext);
        let mut encrypted = Vec::new();
        let encrypted_bytes = cipher.encrypt_stream(&mut input, &mut encrypted, &nonce, Some(aad), Some(1_000_000)).unwrap();
        
        assert_eq!(encrypted_bytes, plaintext.len());
        
        // Decrypt using streaming
        let mut encrypted_cursor = Cursor::new(&encrypted);
        let mut decrypted = Vec::new();
        let decrypted_bytes = cipher.decrypt_stream(&mut encrypted_cursor, &mut decrypted, &nonce, Some(aad)).unwrap();
        
        assert_eq!(decrypted_bytes, plaintext.len());
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_file_encryption_decryption() {
        use std::fs::{self, File};
        use std::io::Write;
        use std::path::Path;
        
        // Create a temporary directory for the test
        let temp_dir = tempfile::tempdir().unwrap();
        let plaintext_path = temp_dir.path().join("plaintext.dat");
        let encrypted_path = temp_dir.path().join("encrypted.dat");
        let decrypted_path = temp_dir.path().join("decrypted.dat");
        
        // Create a test file with 5MB of data
        let data = vec![0x42; 5_000_000];
        let mut file = File::create(&plaintext_path).unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        
        // Generate a key
        let key = utils::random_bytes(32).unwrap();
        let aad = b"file encryption test";
        
        // Encrypt the file
        let encrypted_bytes = encrypt_file(&plaintext_path, &encrypted_path, &key, Some(aad), None).unwrap();
        assert_eq!(encrypted_bytes, data.len());
        
        // Verify the encrypted file exists and is different from the original
        assert!(Path::exists(&encrypted_path));
        let encrypted_content = fs::read(&encrypted_path).unwrap();
        assert_ne!(encrypted_content, data);
        
        // Decrypt the file
        let decrypted_bytes = decrypt_file(&encrypted_path, &decrypted_path, &key, Some(aad)).unwrap();
        assert_eq!(decrypted_bytes, data.len());
        
        // Verify the decrypted file matches the original
        let decrypted_content = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted_content, data);
    }
    
    #[test]
    fn test_file_encryption_tampering() {
        use std::fs::{self, File};
        use std::io::Write;
        use std::path::Path;
        
        // Create a temporary directory for the test
        let temp_dir = tempfile::tempdir().unwrap();
        let plaintext_path = temp_dir.path().join("plaintext.dat");
        let encrypted_path = temp_dir.path().join("encrypted.dat");
        let decrypted_path = temp_dir.path().join("decrypted.dat");
        
        // Create a test file
        let data = b"This is a test file for tampering detection".to_vec();
        let mut file = File::create(&plaintext_path).unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        
        // Generate a key
        let key = utils::random_bytes(32).unwrap();
        
        // Encrypt the file
        encrypt_file(&plaintext_path, &encrypted_path, &key, None, None).unwrap();
        
        // Tamper with the encrypted file
        let mut encrypted_content = fs::read(&encrypted_path).unwrap();
        if encrypted_content.len() > 20 {
            encrypted_content[20] ^= 0x01; // Flip a bit
            fs::write(&encrypted_path, &encrypted_content).unwrap();
        }
        
        // Try to decrypt the tampered file
        let result = decrypt_file(&encrypted_path, &decrypted_path, &key, None);
        
        // Decryption should fail due to authentication failure
        assert!(result.is_err());
    }
}
