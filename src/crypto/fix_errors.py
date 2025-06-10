#!/usr/bin/env python3
import re

def fix_ffi_errors():
    with open('src/ffi.rs', 'r') as f:
        content = f.read()
    
    # Fix buffer size errors
    content = re.sub(
        r'CryptoError::InvalidParameterError\(format!\(\s*"([^"]*) buffer too small\. Required: \{\}, provided: \{\}",\s*([^,]+),\s*([^)]+)\)\)',
        r'CryptoError::invalid_parameter("\1_buffer", &format!("{} bytes", \2), &format!("{} bytes", \3))',
        content,
        flags=re.MULTILINE | re.DOTALL
    )
    
    # Fix simple invalid parameter errors  
    content = re.sub(
        r'CryptoError::InvalidParameterError\(\s*"Invalid ([^"]+)"\.to_string\(\)\s*\)',
        r'CryptoError::invalid_parameter("\1", "valid non-null pointer", "null or invalid")',
        content
    )
    
    with open('src/ffi.rs', 'w') as f:
        f.write(content)

if __name__ == "__main__":
    fix_ffi_errors()
    print("Fixed FFI errors") 