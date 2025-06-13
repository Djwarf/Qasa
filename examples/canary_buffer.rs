use qasa::secure_memory::{CanaryBuffer, DEFAULT_CANARY_PATTERN};
use qasa::error::CryptoError;
use std::ptr;

fn main() {
    println!("Memory Canary Buffer Example");
    println!("===========================\n");

    // Create a buffer with canaries
    let size = 32;
    let mut buffer = CanaryBuffer::new(size, &DEFAULT_CANARY_PATTERN);
    println!("✅ Created a buffer with {} bytes of usable space", size);
    println!("   Canary pattern: {:02X?}", DEFAULT_CANARY_PATTERN);
    println!("   Total buffer size including canaries: {} bytes", 
             size + 2 * DEFAULT_CANARY_PATTERN.len());

    // Example 1: Normal usage
    println!("\nExample 1: Normal Usage");
    let data = b"This is some sensitive data";
    match buffer.write(0, data) {
        Ok(_) => println!("✅ Successfully wrote {} bytes to the buffer", data.len()),
        Err(e) => println!("❌ Failed to write to buffer: {}", e),
    }

    // Read the data back
    let mut output = vec![0u8; data.len()];
    match buffer.read(0, &mut output) {
        Ok(_) => println!("✅ Successfully read data: \"{}\"", String::from_utf8_lossy(&output)),
        Err(e) => println!("❌ Failed to read from buffer: {}", e),
    }

    // Example 2: Bounds checking
    println!("\nExample 2: Bounds Checking");
    let overflow_data = b"This data is too large for the remaining space";
    match buffer.write(10, overflow_data) {
        Ok(_) => println!("✅ Successfully wrote data (unexpected)"),
        Err(e) => println!("✅ Correctly detected potential overflow: {}", e),
    }

    // Example 3: Canary verification
    println!("\nExample 3: Canary Verification");
    println!("   Canaries intact: {}", buffer.verify_canaries());

    // Example 4: Simulating a buffer overflow
    println!("\nExample 4: Simulating Buffer Overflow");
    println!("   This example demonstrates how canaries detect memory corruption");
    
    // Create a new buffer for this example to avoid affecting the previous examples
    let mut overflow_buffer = CanaryBuffer::new(16, &DEFAULT_CANARY_PATTERN);
    println!("   Created a new buffer for overflow demonstration");
    
    // Write some data to the buffer
    let test_data = b"Test data";
    overflow_buffer.write(0, test_data).unwrap();
    println!("   Wrote test data to buffer");
    
    // Manually corrupt the end canary (in a way that's safe in Rust)
    println!("   Simulating memory corruption by directly accessing internal state...");
    
    // This is a contrived example just to show how canaries work
    // We'll create a fake buffer overflow by directly manipulating the buffer
    // through a controlled test function
    corrupt_canary(&mut overflow_buffer);
    
    // Try to access the buffer after corruption
    println!("\n   Attempting to access the buffer after canary corruption:");
    match overflow_buffer.as_slice() {
        Ok(_) => println!("   ❌ Buffer access succeeded (unexpected)"),
        Err(e) => {
            println!("   ✅ Buffer access correctly failed: {}", e);
            if let CryptoError::MemoryError { error_code, .. } = e {
                println!("   Error code: {}", error_code);
            }
        }
    }

    // Example 5: Creating a secure buffer with custom canary pattern
    println!("\nExample 5: Custom Canary Pattern");
    let custom_canary = [0x55, 0xAA, 0x55, 0xAA]; // Alternating bits pattern
    let mut custom_buffer = CanaryBuffer::new(16, &custom_canary);
    println!("✅ Created buffer with custom canary pattern: {:02X?}", custom_canary);
    
    // Write and read data
    let test_data = b"Test data";
    match custom_buffer.write(0, test_data) {
        Ok(_) => println!("✅ Successfully wrote data to buffer with custom canaries"),
        Err(e) => println!("❌ Failed to write to buffer: {}", e),
    }

    // Verify canaries
    println!("   Canaries intact: {}", custom_buffer.verify_canaries());

    println!("\nMemory Security Best Practices:");
    println!("1. Always use bounds checking when accessing memory buffers");
    println!("2. Use canaries to detect buffer overflows and underflows");
    println!("3. Combine with other security measures like ASLR and DEP");
    println!("4. Zero sensitive data after use");
    println!("5. Use memory protection mechanisms when available");
}

// A controlled test function to simulate buffer overflow by corrupting the canary
// This is a safe way to demonstrate the concept without undefined behavior
fn corrupt_canary(buffer: &mut CanaryBuffer) {
    // Get a mutable slice to the buffer data
    if let Ok(slice) = buffer.as_mut_slice() {
        // Write to the last byte of the buffer
        if !slice.is_empty() {
            slice[slice.len() - 1] = 0xFF;
        }
        
        // The canary itself is outside the slice we have access to,
        // so we can't directly corrupt it in safe Rust code.
        // But writing to the edge of the buffer can sometimes cause issues
        // that would be detected by the canary in real-world scenarios.
        println!("   Modified the last byte of the buffer data");
        
        // For demonstration purposes, we'll use an unsafe block to directly
        // corrupt the canary. In real code, this would be a buffer overflow bug.
        unsafe {
            // This is ONLY for demonstration - don't do this in real code!
            let canary_size = DEFAULT_CANARY_PATTERN.len();
            let buffer_ptr = buffer as *mut CanaryBuffer;
            let buffer_ref = &mut *buffer_ptr;
            
            // Get the raw buffer and manually corrupt a byte past the end
            // This simulates what would happen in a real buffer overflow
            if let Ok(data) = buffer_ref.as_mut_slice() {
                if !data.is_empty() {
                    let last_byte_ptr = data.as_mut_ptr().add(data.len() - 1);
                    // Write past the end of the buffer into the canary region
                    ptr::write(last_byte_ptr.add(1), 0xFF);
                    println!("   Corrupted the canary (simulating a buffer overflow)");
                }
            }
        }
    }
} 