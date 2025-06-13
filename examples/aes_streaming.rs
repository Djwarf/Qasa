use qasa::aes::{encrypt_file, decrypt_file};
use qasa::utils;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

fn create_test_file(path: &Path, size_mb: usize) -> io::Result<()> {
    println!("Creating a test file of {}MB...", size_mb);
    let mut file = File::create(path)?;
    
    // Create a 1MB buffer for writing
    let buffer_size = 1_048_576;
    let mut buffer = vec![0u8; buffer_size];
    
    // Fill with random data
    for i in 0..buffer_size {
        buffer[i] = (i % 256) as u8;
    }
    
    // Write the buffer multiple times to reach the desired size
    let start = Instant::now();
    for _ in 0..(size_mb) {
        file.write_all(&buffer)?;
    }
    file.flush()?;
    
    let duration = start.elapsed();
    println!("File created in {:.2?}", duration);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create temporary paths for our test
    let temp_dir = tempfile::tempdir()?;
    let plaintext_path = temp_dir.path().join("large_file.dat");
    let encrypted_path = temp_dir.path().join("large_file.enc");
    let decrypted_path = temp_dir.path().join("large_file_decrypted.dat");
    
    // File size in MB (adjust based on available memory)
    let file_size_mb = 100;
    
    // Create a large test file
    create_test_file(&plaintext_path, file_size_mb)?;
    
    // Generate a random encryption key
    let key = utils::random_bytes(32)?;
    
    // Some associated data for authentication
    let aad = b"Large file encryption example";
    
    // Encrypt the file with different chunk sizes
    println!("\nTesting different chunk sizes for encryption:");
    
    for &chunk_size_mb in &[1, 4, 16] {
        let chunk_size = chunk_size_mb * 1_048_576;
        
        // Remove any existing encrypted file
        let _ = fs::remove_file(&encrypted_path);
        
        println!("\nEncrypting with {}MB chunks:", chunk_size_mb);
        let start = Instant::now();
        let bytes = encrypt_file(&plaintext_path, &encrypted_path, &key, Some(aad), Some(chunk_size))?;
        let duration = start.elapsed();
        
        let throughput = (bytes as f64) / (1_048_576.0 * duration.as_secs_f64());
        println!("Encrypted {} bytes in {:.2?}", bytes, duration);
        println!("Throughput: {:.2} MB/s", throughput);
        
        // Get the size of the encrypted file
        let encrypted_size = fs::metadata(&encrypted_path)?.len();
        println!("Encrypted file size: {} bytes", encrypted_size);
        
        // Remove any existing decrypted file
        let _ = fs::remove_file(&decrypted_path);
        
        // Decrypt the file
        println!("\nDecrypting:");
        let start = Instant::now();
        let bytes = decrypt_file(&encrypted_path, &decrypted_path, &key, Some(aad))?;
        let duration = start.elapsed();
        
        let throughput = (bytes as f64) / (1_048_576.0 * duration.as_secs_f64());
        println!("Decrypted {} bytes in {:.2?}", bytes, duration);
        println!("Throughput: {:.2} MB/s", throughput);
        
        // Verify the decrypted file matches the original
        println!("Verifying decrypted file...");
        let original_hash = calculate_hash(&plaintext_path)?;
        let decrypted_hash = calculate_hash(&decrypted_path)?;
        
        if original_hash == decrypted_hash {
            println!("Verification successful: files match");
        } else {
            println!("ERROR: Decrypted file does not match the original!");
            return Err("Verification failed".into());
        }
    }
    
    println!("\nAll tests completed successfully!");
    Ok(())
}

// Calculate a simple hash of a file for verification
fn calculate_hash(path: &Path) -> io::Result<u64> {
    use std::io::Read;
    
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 8192];
    let mut hash: u64 = 0;
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        for i in 0..bytes_read {
            hash = hash.wrapping_add(buffer[i] as u64);
            hash = hash.wrapping_mul(1_099_511_628_211u64);
        }
    }
    
    Ok(hash)
} 