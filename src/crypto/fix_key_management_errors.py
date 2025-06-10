#!/usr/bin/env python3
import re
import os

def fix_key_management_errors(file_path):
    """Fix KeyManagementError constructor calls to use structured format"""
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Pattern 1: Simple KeyManagementError(format!(...))
    content = re.sub(
        r'CryptoError::KeyManagementError\(\s*format!\(\s*"([^"]+)",\s*([^)]+)\)\s*\)',
        r'CryptoError::key_management_error("operation", &format!("\1", \2), 4001)',
        content
    )
    
    # Pattern 2: KeyManagementError(string.to_string()) or similar
    content = re.sub(
        r'CryptoError::KeyManagementError\(\s*"([^"]+)"\s*\.to_string\(\)\s*\)',
        r'CryptoError::key_management_error("operation", "\1", 4001)',
        content
    )
    
    # Pattern 3: KeyManagementError("literal string")
    content = re.sub(
        r'CryptoError::KeyManagementError\(\s*"([^"]+)"\s*\)',
        r'CryptoError::key_management_error("operation", "\1", 4001)',
        content
    )
    
    # More specific patterns for this file
    replacements = [
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Key {} does not exist",\s*key_id\s*\)\s*\)',
         r'CryptoError::key_management_error("load_key", &format!("Key {} does not exist", key_id), 4001)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to delete key file: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("delete_key", &format!("Failed to delete key file: {}", e), 4002)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Invalid key type: {}",\s*key_type\s*\)\s*\)',
         r'CryptoError::key_management_error("load_key", &format!("Invalid key type: {}", key_type), 4003)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to create export file: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("export_key", &format!("Failed to create export file: {}", e), 4004)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to write export file: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("export_key", &format!("Failed to write export file: {}", e), 4005)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to open export file: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("import_key", &format!("Failed to open export file: {}", e), 4006)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to read export file: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("import_key", &format!("Failed to read export file: {}", e), 4007)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Invalid key type in import file: {}",\s*key_type\s*\)\s*\)',
         r'CryptoError::key_management_error("import_key", &format!("Invalid key type in import file: {}", key_type), 4008)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to create metadata file: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("rotate_key", &format!("Failed to create metadata file: {}", e), 4009)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to write metadata: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("rotate_key", &format!("Failed to write metadata: {}", e), 4010)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to open metadata file: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("get_key_age", &format!("Failed to open metadata file: {}", e), 4011)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to read metadata: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("get_key_age", &format!("Failed to read metadata: {}", e), 4012)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to read key directory: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("list_keys", &format!("Failed to read key directory: {}", e), 4013)'),
        
        (r'CryptoError::KeyManagementError\(\s*format!\(\s*"Failed to read directory entry: {}",\s*e\s*\)\s*\)',
         r'CryptoError::key_management_error("list_keys", &format!("Failed to read directory entry: {}", e), 4014)'),
    ]
    
    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)
    
    with open(file_path, 'w') as f:
        f.write(content)

# Fix all key management files
files_to_fix = [
    'src/key_management/storage.rs',
    'src/key_management/rotation.rs'
]

for file_path in files_to_fix:
    if os.path.exists(file_path):
        print(f"Fixing {file_path}...")
        fix_key_management_errors(file_path)
        print(f"Fixed {file_path}")
    else:
        print(f"File not found: {file_path}")

print("Done fixing KeyManagementError calls") 