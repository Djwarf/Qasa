/*!
 * Example demonstrating the fully functional quantum-safe protocols
 * 
 * This example shows:
 * 1. Quantum-safe TLS handshake and secure communication
 * 2. Secure messaging with contact management
 * 3. Key rotation and forward secrecy
 */

use qasa::protocols::{
    QuantumSafeTLS, TlsConfig, CipherSuite,
    SecureMessaging, MessagingConfig, TrustLevel,
};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== QaSa Protocols Demo ===\n");

    // Demo 1: Quantum-Safe TLS
    demo_quantum_safe_tls()?;
    
    println!("\n" + "=".repeat(50).as_str() + "\n");
    
    // Demo 2: Secure Messaging
    demo_secure_messaging()?;
    
    Ok(())
}

fn demo_quantum_safe_tls() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. Quantum-Safe TLS Demo");
    println!("------------------------");
    
    // Configure TLS
    let config = TlsConfig {
        max_sessions: 100,
        session_timeout: Duration::from_secs(3600),
        supported_cipher_suites: vec![
            CipherSuite::Kyber768_Dilithium3_AES256GCM,
            CipherSuite::Kyber1024_Dilithium5_AES256GCM,
        ],
        require_client_authentication: false,
        enable_session_resumption: true,
    };
    
    // Create client and server
    let mut client = QuantumSafeTLS::new(config.clone())?;
    let mut server = QuantumSafeTLS::new(config)?;
    
    println!("✓ Created TLS client and server");
    
    // Step 1: Client initiates handshake
    println!("\n→ Client sending ClientHello...");
    let client_hello = client.client_hello()?;
    println!("  - Kyber public key size: {} bytes", client_hello.kyber_public_key.len());
    println!("  - Supported cipher suites: {:?}", client_hello.cipher_suites);
    
    // Step 2: Server responds with ServerHello
    println!("\n← Server processing ClientHello and sending ServerHello...");
    let server_hello = server.server_hello(&client_hello)?;
    println!("  - Selected cipher suite: {:?}", server_hello.cipher_suite);
    println!("  - Kyber ciphertext size: {} bytes", server_hello.kyber_ciphertext.len());
    println!("  - Certificate size: {} bytes", server_hello.certificate.len());
    println!("  - Signature size: {} bytes", server_hello.signature.len());
    
    // Step 3: Client completes handshake
    println!("\n→ Client processing ServerHello...");
    let handshake = client.process_server_hello(&server_hello)?;
    println!("  - Handshake complete!");
    println!("  - Session ID: {:?}", hex::encode(&handshake.session_id[..8]));
    
    // Step 4: Establish secure sessions
    println!("\n↔ Establishing secure sessions...");
    let client_session = client.establish_session(&handshake)?;
    let server_session = server.establish_session(&handshake)?;
    println!("  - Client session established");
    println!("  - Server session established");
    
    // Step 5: Exchange encrypted data
    println!("\n↔ Exchanging encrypted application data...");
    let test_messages = vec![
        "Hello from quantum-safe TLS!",
        "This message is protected by post-quantum cryptography.",
        "Even quantum computers can't break this encryption!",
    ];
    
    for (i, message) in test_messages.iter().enumerate() {
        // Client encrypts and sends
        let encrypted = client.encrypt_data(message.as_bytes(), &client_session)?;
        println!("\n  Message {}: \"{}\"", i + 1, message);
        println!("  - Encrypted size: {} bytes", encrypted.len());
        
        // Server decrypts
        let decrypted = server.decrypt_data(&encrypted, &server_session)?;
        let decrypted_str = String::from_utf8(decrypted)?;
        println!("  - Server decrypted: \"{}\"", decrypted_str);
        
        assert_eq!(message, &decrypted_str);
    }
    
    println!("\n✓ TLS communication successful!");
    println!("  - Active sessions on server: {}", server.active_sessions());
    
    Ok(())
}

fn demo_secure_messaging() -> Result<(), Box<dyn std::error::Error>> {
    println!("2. Secure Messaging Demo");
    println!("------------------------");
    
    // Configure messaging
    let config = MessagingConfig {
        max_ephemeral_keys: 50,
        key_rotation_interval: Duration::from_secs(3600),
        message_expiry: Duration::from_secs(86400 * 7),
        enable_forward_secrecy: true,
    };
    
    // Create three users: Mary, Elena, and Charlie
    let mut mary = SecureMessaging::new(
        "mary@quantum.safe".to_string(),
        "Mary".to_string(),
        config.clone()
    )?;
    
    let mut elena = SecureMessaging::new(
        "elena@quantum.safe".to_string(),
        "Elena".to_string(),
        config.clone()
    )?;
    
    let mut charlie = SecureMessaging::new(
        "charlie@quantum.safe".to_string(),
        "Charlie".to_string(),
        config
    )?;
    
    println!("✓ Created secure messaging instances for Mary, Elena, and Charlie");
    
    // Exchange public keys
    let (mary_kyber, mary_dilithium) = mary.get_own_public_keys();
    let (elena_kyber, elena_dilithium) = elena.get_own_public_keys();
    let (charlie_kyber, charlie_dilithium) = charlie.get_own_public_keys();
    
    // Mary adds Elena and Charlie as contacts
    println!("\n→ Mary adding contacts...");
    mary.add_contact(
        "elena@quantum.safe".to_string(),
        "Elena".to_string(),
        elena_kyber.clone(),
        elena_dilithium.clone(),
    )?;
    
    mary.add_contact(
        "charlie@quantum.safe".to_string(),
        "Charlie".to_string(),
        charlie_kyber.clone(),
        charlie_dilithium.clone(),
    )?;
    
    // Elena adds Mary
    elena.add_contact(
        "mary@quantum.safe".to_string(),
        "Mary".to_string(),
        mary_kyber.clone(),
        mary_dilithium.clone(),
    )?;
    
    // List Mary's contacts
    let contacts = mary.list_contacts();
    println!("  - Mary's contacts:");
    for (id, name, trust) in &contacts {
        println!("    • {} ({}) - Trust: {:?}", name, id, trust);
    }
    
    // Mary verifies Elena
    println!("\n→ Mary verifying Elena's identity...");
    mary.verify_contact(&"elena@quantum.safe".to_string())?;
    let contacts = mary.list_contacts();
    let elena_contact = contacts.iter().find(|(id, _, _)| id == "elena@quantum.safe").unwrap();
    println!("  - Elena's trust level updated to: {:?}", elena_contact.2);
    
    // Send messages
    println!("\n↔ Exchanging secure messages...");
    
    // Mary sends to Elena
    let message1 = "Hey Elena! This is a quantum-safe message.";
    println!("\n  Mary → Elena: \"{}\"", message1);
    let encrypted1 = mary.send_message(&"elena@quantum.safe".to_string(), message1.as_bytes())?;
    println!("  - Message ID: {}", hex::encode(&encrypted1.message_id[..8]));
    println!("  - Encrypted size: {} bytes", encrypted1.encrypted_content.len());
    
    // Elena receives from Mary
    let decrypted1 = elena.receive_message(&encrypted1)?;
    let decrypted1_str = String::from_utf8(decrypted1)?;
    println!("  - Elena decrypted: \"{}\"", decrypted1_str);
    
    // Elena replies to Mary
    let message2 = "Hi Mary! Got your message loud and clear!";
    println!("\n  Elena → Mary: \"{}\"", message2);
    let encrypted2 = elena.send_message(&"mary@quantum.safe".to_string(), message2.as_bytes())?;
    
    // Mary receives from Elena
    let decrypted2 = mary.receive_message(&encrypted2)?;
    let decrypted2_str = String::from_utf8(decrypted2)?;
    println!("  - Mary decrypted: \"{}\"", decrypted2_str);
    
    // Test replay protection
    println!("\n→ Testing replay protection...");
    match elena.receive_message(&encrypted1) {
        Err(e) => println!("  ✓ Replay attack blocked: {}", e),
        Ok(_) => panic!("Replay attack should have been blocked!"),
    }
    
    // Export/Import contact
    println!("\n→ Testing contact export/import...");
    let elena_export = mary.export_contact(&"elena@quantum.safe".to_string())?;
    println!("  - Exported Elena's contact: {} bytes", elena_export.len());
    
    // Charlie imports Elena's contact from Mary
    charlie.import_contact(&elena_export)?;
    let charlie_contacts = charlie.list_contacts();
    println!("  - Charlie's contacts after import:");
    for (id, name, trust) in &charlie_contacts {
        println!("    • {} ({}) - Trust: {:?}", name, id, trust);
    }
    
    // Charlie adds Mary to send her a message
    charlie.add_contact(
        "mary@quantum.safe".to_string(),
        "Mary".to_string(),
        mary_kyber,
        mary_dilithium,
    )?;
    
    // Charlie sends to Mary
    let message3 = "Hi Mary! Elena shared your contact with me.";
    println!("\n  Charlie → Mary: \"{}\"", message3);
    let encrypted3 = charlie.send_message(&"mary@quantum.safe".to_string(), message3.as_bytes())?;
    
    // Mary receives from Charlie
    let decrypted3 = mary.receive_message(&encrypted3)?;
    let decrypted3_str = String::from_utf8(decrypted3)?;
    println!("  - Mary decrypted: \"{}\"", decrypted3_str);
    
    println!("\n✓ Secure messaging successful!");
    
    Ok(())
} 