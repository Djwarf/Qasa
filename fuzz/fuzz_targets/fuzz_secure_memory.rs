#![no_main]

use libfuzzer_sys::fuzz_target;
use qasa::secure_memory::{CanaryBuffer, DEFAULT_CANARY_PATTERN, SecureBuffer, SecureBytes, LockedBuffer};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct SecureMemoryFuzzInput {
    buffer_size: usize,
    canary_pattern: Vec<u8>,
    write_data: Vec<u8>,
    write_offset: usize,
    read_size: usize,
    read_offset: usize,
}

fuzz_target!(|input: SecureMemoryFuzzInput| {
    // Limit buffer size to avoid excessive memory usage
    let buffer_size = input.buffer_size % 1024;
    
    // Test CanaryBuffer
    if buffer_size > 0 {
        // Use default or provided canary pattern
        let canary_pattern = if input.canary_pattern.is_empty() {
            &DEFAULT_CANARY_PATTERN
        } else {
            &input.canary_pattern
        };
        
        // Create a canary buffer
        let mut buffer = CanaryBuffer::new(buffer_size, canary_pattern);
        
        // Test writing to the buffer
        if !input.write_data.is_empty() {
            let _ = buffer.write(input.write_offset % (buffer_size + 1), &input.write_data);
        }
        
        // Test reading from the buffer
        let read_size = input.read_size % (buffer_size + 1);
        if read_size > 0 {
            let mut output = vec![0u8; read_size];
            let _ = buffer.read(input.read_offset % (buffer_size + 1), &mut output);
        }
        
        // Test getting slices
        let _ = buffer.as_slice();
        let _ = buffer.as_mut_slice();
        
        // Test canary verification
        let _ = buffer.verify_canaries();
        let _ = buffer.check_canaries();
    }
    
    // Test SecureBuffer
    {
        let data = input.write_data.clone();
        let secure_buffer = SecureBuffer::new(data);
        let _ = secure_buffer.as_ref();
    }
    
    // Test SecureBytes
    {
        let secure_bytes = SecureBytes::new(&input.write_data);
        let _ = secure_bytes.as_bytes();
        
        if !input.write_data.is_empty() {
            let mut mutable_bytes = SecureBytes::new(&input.write_data);
            let _ = mutable_bytes.as_bytes_mut();
        }
    }
    
    // Test LockedBuffer (only if buffer size is reasonable)
    if buffer_size > 0 && buffer_size < 128 {
        // Try to create a locked buffer
        let _ = LockedBuffer::with_capacity(buffer_size);
        
        if !input.write_data.is_empty() {
            let _ = LockedBuffer::new(&input.write_data);
        }
    }
});
