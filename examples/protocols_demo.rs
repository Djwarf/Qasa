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
    
    // Create three users: Alice, Bob, and Charlie
    let mut alice = SecureMessaging::new(
        "alice@quantum.safe".to_string(),
        "Alice".to_string(),
        config.clone()
    )?;
    
    let mut bob = SecureMessaging::new(
        "bob@quantum.safe".to_string(),
        "Bob".to_string(),
        config.clone()
    )?;
    
    let mut charlie = SecureMessaging::new(
        "charlie@quantum.safe".to_string(),
        "Charlie".to_string(),
        config
    )?;
    
    println!("✓ Created secure messaging instances for Alice, Bob, and Charlie");
    
    // Exchange public keys
    let (alice_kyber, alice_dilithium) = alice.get_own_public_keys();
    let (bob_kyber, bob_dilithium) = bob.get_own_public_keys();
    let (charlie_kyber, charlie_dilithium) = charlie.get_own_public_keys();
    
    // Alice adds Bob and Charlie as contacts
    println!("\n→ Alice adding contacts...");
    alice.add_contact(
        "bob@quantum.safe".to_string(),
        "Bob".to_string(),
        bob_kyber.clone(),
        bob_dilithium.clone(),
    )?;
    
    alice.add_contact(
        "charlie@quantum.safe".to_string(),
        "Charlie".to_string(),
        charlie_kyber.clone(),
        charlie_dilithium.clone(),
    )?;
    
    // Bob adds Alice
    bob.add_contact(
        "alice@quantum.safe".to_string(),
        "Alice".to_string(),
        alice_kyber.clone(),
        alice_dilithium.clone(),
    )?;
    
    // List Alice's contacts
    let contacts = alice.list_contacts();
    println!("  - Alice's contacts:");
    for (id, name, trust) in &contacts {
        println!("    • {} ({}) - Trust: {:?}", name, id, trust);
    }
    
    // Alice verifies Bob
    println!("\n→ Alice verifying Bob's identity...");
    alice.verify_contact(&"bob@quantum.safe".to_string())?;
    let contacts = alice.list_contacts();
    let bob_contact = contacts.iter().find(|(id, _, _)| id == "bob@quantum.safe").unwrap();
    println!("  - Bob's trust level updated to: {:?}", bob_contact.2);
    
    // Send messages
    println!("\n↔ Exchanging secure messages...");
    
    // Alice sends to Bob
    let message1 = "Hey Bob! This is a quantum-safe message.";
    println!("\n  Alice → Bob: \"{}\"", message1);
    let encrypted1 = alice.send_message(&"bob@quantum.safe".to_string(), message1.as_bytes())?;
    println!("  - Message ID: {}", hex::encode(&encrypted1.message_id[..8]));
    println!("  - Encrypted size: {} bytes", encrypted1.encrypted_content.len());
    
    // Bob receives from Alice
    let decrypted1 = bob.receive_message(&encrypted1)?;
    let decrypted1_str = String::from_utf8(decrypted1)?;
    println!("  - Bob decrypted: \"{}\"", decrypted1_str);
    
    // Bob replies to Alice
    let message2 = "Hi Alice! Got your message loud and clear!";
    println!("\n  Bob → Alice: \"{}\"", message2);
    let encrypted2 = bob.send_message(&"alice@quantum.safe".to_string(), message2.as_bytes())?;
    
    // Alice receives from Bob
    let decrypted2 = alice.receive_message(&encrypted2)?;
    let decrypted2_str = String::from_utf8(decrypted2)?;
    println!("  - Alice decrypted: \"{}\"", decrypted2_str);
    
    // Test replay protection
    println!("\n→ Testing replay protection...");
    match bob.receive_message(&encrypted1) {
        Err(e) => println!("  ✓ Replay attack blocked: {}", e),
        Ok(_) => panic!("Replay attack should have been blocked!"),
    }
    
    // Export/Import contact
    println!("\n→ Testing contact export/import...");
    let bob_export = alice.export_contact(&"bob@quantum.safe".to_string())?;
    println!("  - Exported Bob's contact: {} bytes", bob_export.len());
    
    // Charlie imports Bob's contact from Alice
    charlie.import_contact(&bob_export)?;
    let charlie_contacts = charlie.list_contacts();
    println!("  - Charlie's contacts after import:");
    for (id, name, trust) in &charlie_contacts {
        println!("    • {} ({}) - Trust: {:?}", name, id, trust);
    }
    
    // Charlie adds Alice to send her a message
    charlie.add_contact(
        "alice@quantum.safe".to_string(),
        "Alice".to_string(),
        alice_kyber,
        alice_dilithium,
    )?;
    
    // Charlie sends to Alice
    let message3 = "Hi Alice! Bob shared your contact with me.";
    println!("\n  Charlie → Alice: \"{}\"", message3);
    let encrypted3 = charlie.send_message(&"alice@quantum.safe".to_string(), message3.as_bytes())?;
    
    // Alice receives from Charlie
    let decrypted3 = alice.receive_message(&encrypted3)?;
    let decrypted3_str = String::from_utf8(decrypted3)?;
    println!("  - Alice decrypted: \"{}\"", decrypted3_str);
    
    println!("\n✓ Secure messaging successful!");
    
    Ok(())
} 