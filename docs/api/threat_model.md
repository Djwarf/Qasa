# QaSa Cryptography Module Threat Model

## Introduction

This document describes the threat model for the QaSa cryptography module, which provides post-quantum cryptographic primitives for secure communication applications. Understanding the threats, attack vectors, and security boundaries is essential for properly implementing and using the module.

**Last Updated:** May 2024
**Current Version:** 0.0.5

## System Context

The QaSa cryptography module is designed to be a component in end-to-end secure communication systems, providing:

1. Post-quantum key exchange (CRYSTALS-Kyber)
2. Post-quantum digital signatures (CRYSTALS-Dilithium and SPHINCS+)
3. Authenticated symmetric encryption (AES-GCM)
4. Secure key management
5. Hardware Security Module (HSM) integration
6. WebAssembly (WASM) support
7. Python language bindings
8. Formal verification tools

The module is implemented in Rust, chosen for its memory safety guarantees and performance. It relies on the following external dependencies:

- OQS (Open Quantum Safe) for post-quantum cryptography
- The Rust `aes-gcm` crate for symmetric encryption
- The Rust `argon2` crate for password-based key derivation
- The Rust `zeroize` crate for secure memory handling
- The Rust `pkcs11` crate for HSM integration
- The Rust `pyo3` crate for Python bindings
- The Rust `wasm-bindgen` crate for WebAssembly support

## Assets to Protect

The primary assets the cryptography module aims to protect are:

1. **Private/Secret Keys**
   - Kyber secret keys
   - Dilithium signing keys
   - Shared secrets derived from key exchange
   - Password-derived encryption keys
   - HSM-protected keys and credentials

2. **User Data**
   - Message plaintext
   - Message metadata
   - User identity information

3. **System Integrity**
   - Ensuring communications are not tampered with
   - Verifying the authenticity of messages
   - Maintaining key rotation schedules
   - Preserving security properties across platforms (native, WASM, etc.)

## Threat Actors

### External Network Adversary

**Capabilities:**
- Can observe, intercept, and modify network traffic
- May control network infrastructure
- May perform traffic analysis
- Potentially has access to quantum computing resources

**Motivations:**
- Reading sensitive communications
- Impersonating users
- Modifying messages
- Performing denial of service attacks

### Local System Adversary

**Capabilities:**
- Can access the file system where keys are stored
- May be able to observe process memory (with some limitations)
- Can influence the environment the application runs in
- May have some access to side-channel information

**Motivations:**
- Stealing cryptographic keys
- Decrypting previously captured messages
- Impersonating the user

### Advanced Persistent Threat (APT)

**Capabilities:**
- Sophisticated techniques and resources
- Long-term access to systems
- Custom attack tools
- Potentially state-sponsored

**Motivations:**
- Long-term surveillance
- Targeted attacks against specific users
- Collection of intelligence

### Quantum Adversary

**Capabilities:**
- Access to large-scale quantum computers
- Ability to run Shor's algorithm against traditional cryptography
- Ability to run Grover's algorithm against symmetric cryptography

**Motivations:**
- Breaking currently secure communications
- Decrypting previously captured encrypted traffic
- Breaking digital signatures for forgery

### Memory Dumping Adversary

**Capabilities:**
- Ability to capture memory dumps of a running process
- Tools to scan memory for cryptographic keys
- Cold boot attacks against system RAM
- Debug capabilities to analyze memory

**Motivations:**
- Extracting cryptographic keys from memory
- Bypassing disk encryption by capturing keys from RAM
- Circumventing secure key storage mechanisms

### Web/Browser-Based Adversary

**Capabilities:**
- Access to browser debugging tools
- Ability to inspect WebAssembly memory
- Can execute JavaScript in the same context
- Can manipulate DOM and browser environment

**Motivations:**
- Extracting cryptographic keys from browser memory
- Intercepting sensitive data in web applications
- Bypassing client-side security controls

## Attack Vectors and Mitigations

### Network-Based Attacks

| Attack Vector | Description | Mitigation |
|---------------|-------------|------------|
| Man-in-the-Middle | Attacker positions themselves between communicating parties | Post-quantum authenticated key exchange; digital signatures to verify identities |
| Traffic Analysis | Analyzing patterns in communication to infer information | Not directly addressed; application layer should implement padding and traffic normalization |
| Replay Attacks | Capturing and replaying previous communications | Nonces and timestamps included in authenticated data; sequence numbers where appropriate |
| Protocol Downgrade | Forcing the use of weaker cryptographic algorithms | Strict protocol version checking; no fallback to non-PQ algorithms |

### Cryptographic Attacks

| Attack Vector | Description | Mitigation |
|---------------|-------------|------------|
| Quantum Computing | Using quantum algorithms to break cryptography | Use of post-quantum algorithms (Kyber, Dilithium, SPHINCS+); algorithm diversity; sufficiently large AES-256 keys |
| Side-Channel Analysis | Extracting keys by analyzing timing, power, etc. | Constant-time operations where possible; memory zeroization; secure comparison functions; formal verification of constant-time properties |
| Implementation Flaws | Bugs in cryptographic implementation | Use of well-vetted libraries; comprehensive test suite; security audits; formal verification of algorithm correctness |
| Random Number Generation Flaws | Predictable "random" values used for keys/nonces | Use of OS-provided secure random number generation; entropy checking |

### Key Management Attacks

| Attack Vector | Description | Mitigation |
|---------------|-------------|------------|
| Key Extraction from Storage | Accessing stored key material | Encrypted key storage with password protection; key material never stored in plaintext; HSM integration for critical keys |
| Memory Dumping | Extracting keys from process memory | Secure memory handling with zeroization; minimizing key lifetime in memory; use of SecureBuffer and SecureBytes containers |
| Weak Passwords | Brute-forcing password-protected keys | Argon2id with strong parameters; encouraging strong passwords (application responsibility) |
| Key Reuse | Using the same key for too long | Key rotation policies; tracking key age; automatic rotation capabilities |
| Old Key Recovery | Recovering previously rotated keys | Limiting the number of old keys stored; automatic secure deletion of expired keys |

### System-Level Attacks

| Attack Vector | Description | Mitigation |
|---------------|-------------|------------|
| Malicious Dependencies | Supply chain attacks in dependencies | Dependency vetting and pinning; minimizing dependency count |
| Operating System Compromise | Attacker controls the OS | Limited scope; cryptographic operations protect data even on compromised systems to the extent possible; HSM integration for critical keys |
| Cold Boot Attacks | Extracting keys from RAM after power-off | Memory zeroization; minimizing key material in memory; use of SecureBytes for sensitive data; HSM integration |
| Process Memory Scanning | Scanning process memory for key patterns | Memory zeroization; use of Zeroize and ZeroizeOnDrop traits; with_secure_scope function |

### WebAssembly-Specific Attacks

| Attack Vector | Description | Mitigation |
|---------------|-------------|------------|
| WASM Memory Inspection | Inspecting WebAssembly memory directly | Secure memory handling in WASM context; minimizing key lifetime in memory |
| JavaScript Interception | Intercepting data passed between JS and WASM | Minimizing data transfer; secure handling of sensitive data in JavaScript |
| Browser Developer Tools | Using browser tools to inspect memory | Memory zeroization; minimizing key lifetime; avoiding console logging of sensitive data |
| Cross-Site Scripting (XSS) | Injecting malicious code that can access WASM memory | Not directly addressed; application must implement proper XSS protections |

### HSM-Related Attacks

| Attack Vector | Description | Mitigation |
|---------------|-------------|------------|
| PIN/Credential Theft | Stealing HSM access credentials | Secure handling of HSM PINs; minimizing PIN lifetime in memory |
| HSM Library Manipulation | Replacing or manipulating HSM library | Library path verification; integrity checking of HSM libraries |
| HSM API Attacks | Exploiting vulnerabilities in HSM API | Proper error handling; input validation for HSM operations |
| Physical HSM Attacks | Physical tampering with HSM hardware | Outside scope; rely on HSM physical security features |

## Memory Security Mitigations

The module implements several layers of defense against memory-based attacks:

1. **SecureBuffer and SecureBytes Containers**
   - Specialized container types that automatically zeroize memory on drop
   - Minimize the risk of sensitive data leaking in memory dumps
   - Properly implement Zeroize and ZeroizeOnDrop traits

2. **with_secure_scope Function**
   - Ensures sensitive data is zeroized even when functions return early due to errors
   - Uses scope guards to guarantee cleanup even during panics
   - Creates a clear pattern for securely handling sensitive data

3. **Explicit Memory Zeroization**
   - All sensitive data structures implement Zeroize trait
   - Manual calls to zeroize() where needed
   - Constant-time comparison functions to prevent timing attacks

4. **Minimized Data Lifetime**
   - Sensitive data is kept in memory only as long as necessary
   - Scope-limited variables for sensitive operations
   - Proper cloning to avoid borrowing issues with sensitive data

5. **SecureBytes Usage Guidelines**
   - Guidelines for when to use SecureBytes vs. regular Vec<u8>
   - Patterns for securely passing sensitive data between functions
   - Documentation of memory security considerations

6. **WebAssembly Memory Protection**
   - Special handling for WASM memory environment
   - WASM-specific secure memory containers
   - Minimizing data transfer between JavaScript and WASM

7. **HSM Integration**
   - Critical keys can be stored and used within HSMs
   - Keys never leave the HSM boundary for operations
   - Reduces exposure of key material in application memory

## Key Rotation Security Mitigations

The module implements a comprehensive key rotation system:

1. **Flexible Rotation Policies**
   - Configurable rotation intervals (30, 90, or 365 days)
   - Options for high, standard, and minimal security
   - Automatic detection of keys due for rotation

2. **Rotation Metadata**
   - Tracking of key creation and last rotation dates
   - Secure storage of rotation metadata alongside keys
   - Key relationship tracking (previous versions of rotated keys)

3. **Seamless Key Transition**
   - Maintaining algorithm consistency during rotation
   - Option to preserve or delete old keys after rotation
   - Configurable limit on the number of old keys to retain

4. **Key Age Management**
   - Functions to check key age and rotation status
   - Warnings when keys approach rotation deadlines
   - Human-readable status descriptions for key age

5. **Automatic Rotation**
   - Background rotation of keys according to policy
   - Secure password handling during automatic rotation
   - Error recovery for failed rotation operations

6. **HSM-Aware Rotation**
   - Support for rotating keys stored in HSMs
   - Maintaining HSM security properties during rotation
   - HSM-specific rotation policies

## Formal Verification Security Mitigations

The module implements formal verification tools to mathematically prove security properties:

1. **Constant-Time Verification**
   - Mathematical verification of constant-time implementations
   - Detection of timing side channels in cryptographic operations
   - Verification of branch-free code paths for sensitive operations

2. **Algorithm Correctness**
   - Formal verification of cryptographic algorithm correctness
   - Ensuring implementations match mathematical specifications
   - Verification of key security properties

3. **Side-Channel Resistance**
   - Analysis of potential side-channel vulnerabilities
   - Verification of countermeasures against known attacks
   - Comprehensive testing of side-channel resistance

4. **Protocol Security**
   - Verification of cryptographic protocol security properties
   - Analysis of key exchange and signature protocols
   - Detection of potential protocol vulnerabilities

5. **Verification Reporting**
   - Detailed reports on verification results
   - Confidence metrics for verification findings
   - Recommendations for addressing identified issues

## Security Boundaries and Trust Assumptions

### Within Security Boundary

The module aims to protect against:

1. Attacks against the cryptographic algorithms themselves
2. Improper handling of sensitive key material in memory
3. Insecure storage of cryptographic keys
4. Message tampering and forgery
5. Quantum computer attacks against the cryptography
6. Memory dumping attacks targeting sensitive data
7. Key overuse through automatic rotation mechanisms
8. Side-channel attacks through constant-time implementations and formal verification

### Outside Security Boundary

The module cannot protect against:

1. Physical attacks on the hardware (except when using HSMs)
2. Compromise of the operating system or runtime environment
3. Malware on the user's device
4. Social engineering attacks against users
5. Attacks against the application using this module incorrectly
6. Side-channel attacks specific to the hardware/environment
7. Users choosing extremely weak passwords
8. Browser/JavaScript environment compromise when using WASM

### Trust Assumptions

The module assumes:

1. The operating system's random number generator is secure
2. The user can securely enter and manage passwords
3. The underlying cryptographic libraries correctly implement the algorithms
4. The compiler and build process don't introduce backdoors
5. The execution environment prevents other processes from accessing the application's memory
6. The platform supports proper memory zeroization (not defeated by compiler optimizations)
7. The diverse set of cryptographic algorithms (lattice-based and hash-based) provides protection against future cryptanalytic breakthroughs
8. HSM providers properly implement security boundaries
9. The browser environment properly isolates WASM memory when using WebAssembly

## Specific Scenarios and Mitigations

### Scenario 1: Adversary Captures Network Traffic

**Attack Path:**
1. Adversary captures encrypted traffic
2. Attempts to decrypt using quantum computing resources
3. If successful, accesses plaintext messages

**Mitigations:**
- Use of post-quantum Kyber for key exchange resists quantum attacks
- Multiple signature algorithms (Dilithium and SPHINCS+) provide algorithm diversity
- AES-256 provides adequate security margin against Grover's algorithm
- Forward secrecy through automatic key rotation limits impact of key compromise

### Scenario 2: Adversary Accesses Key Storage

**Attack Path:**
1. Adversary gains access to the key storage directory
2. Attempts to decrypt key files using password attacks
3. If successful, uses keys to decrypt messages or forge signatures

**Mitigations:**
- Keys are never stored in plaintext
- Keys are encrypted with password-derived keys using Argon2id
- Strong Argon2id parameters increase resistance to brute-force attacks
- Automatic key rotation ensures stolen keys have limited utility
- Critical keys can be stored in HSMs, preventing direct access

### Scenario 3: Memory Extraction Attack

**Attack Path:**
1. Adversary dumps process memory
2. Searches for cryptographic keys or plaintext
3. Uses extracted information to compromise security

**Mitigations:**
- Sensitive data structures implement Zeroize trait
- SecureBuffer and SecureBytes containers automatically zeroize on drop
- with_secure_scope function ensures zeroization even on early returns
- Key material kept in memory only as long as necessary
- HSM integration keeps critical keys outside of process memory

### Scenario 4: Side-Channel Attack

**Attack Path:**
1. Adversary measures timing, power consumption, or other side channels
2. Uses gathered information to infer key bits
3. Reconstructs cryptographic keys

**Mitigations:**
- Use of constant-time comparison functions for sensitive operations
- Reliance on libraries that implement algorithms with side-channel resistance
- Minimizing branches based on secret data
- Warning developers about potential side channels in documentation
- Formal verification of constant-time implementations

### Scenario 5: Key Overuse Attack

**Attack Path:**
1. Adversary collects large amounts of data encrypted with the same key
2. Performs cryptanalysis to identify patterns or weaknesses
3. Eventually compromises the key or specific messages

**Mitigations:**
- Automatic key rotation based on configurable policies
- Key age tracking to identify keys in need of rotation
- Secure handling of key history for compatibility with old messages
- Limiting the retention of old keys to reduce exposure

### Scenario 6: WebAssembly Memory Inspection

**Attack Path:**
1. Adversary uses browser developer tools to inspect WASM memory
2. Locates cryptographic keys or sensitive data in memory
3. Extracts keys to decrypt communications

**Mitigations:**
- WASM-specific secure memory handling
- Minimizing key lifetime in WASM memory
- Zeroization of sensitive data after use
- Avoiding direct exposure of key material to JavaScript

### Scenario 7: HSM Credential Theft

**Attack Path:**
1. Adversary gains access to HSM PIN or credentials
2. Uses credentials to access keys stored in HSM
3. Performs unauthorized cryptographic operations

**Mitigations:**
- Secure handling of HSM credentials
- Minimizing credential lifetime in memory
- Role-based access control for HSM operations
- Audit logging of HSM access attempts

## Risk Analysis

| Risk | Likelihood | Impact | Mitigation Effectiveness | Residual Risk |
|------|------------|--------|--------------------------|---------------|
| Quantum Computing Attack | Medium | High | High (Post-quantum cryptography) | Low |
| Side-Channel Attack | Medium | High | High (Formal verification, constant-time ops) | Low |
| Key Storage Compromise | Medium | High | High (Password-protected, encrypted storage, HSM) | Low |
| Memory Extraction | Medium | High | High (Secure memory handling) | Low |
| Implementation Flaws | Medium | High | High (Testing, audits, formal verification) | Low |
| Weak Password Selection | High | High | Low (Outside module control) | High |
| Random Number Generator Compromise | Low | High | Medium (OS RNG dependency) | Medium |
| Key Overuse | Medium | Medium | High (Automatic rotation) | Low |
| Cold Boot Attack | Low | High | Medium (Memory zeroization, HSM) | Low |
| WASM Memory Inspection | Medium | High | Medium (WASM memory protection) | Medium |
| HSM API Attacks | Low | High | Medium (Input validation, error handling) | Medium |

## Continuous Improvement

The threat model is a living document and should be updated as:

1. New cryptographic attacks are discovered
2. The post-quantum cryptography landscape evolves
3. New vulnerabilities are found in dependencies
4. Additional features are added to the module
5. New memory protection techniques become available
6. Key rotation policies need adjustment based on threat intelligence
7. WebAssembly security best practices evolve
8. HSM integration capabilities expand

Regular security reviews and updates to this threat model are recommended, with a minimum annual review cycle.

## Reporting Security Issues

If you discover security vulnerabilities or have concerns about this threat model, please contact:

- djwarfqasa@proton.me

Responsible disclosure is requested - please allow time for issues to be addressed before public disclosure.

## References

1. NIST SP 800-208: CRYSTALS-Kyber, CRYSTALS-Dilithium, and SPHINCS+
2. NIST SP 800-38D: AES-GCM
3. RFC 9106: Argon2 Password Hashing
4. NIST SP 800-175B: Guideline for Using Cryptographic Standards
5. "Post-Quantum Cryptography: Current State and Quantum Mitigation" (Mosca, 2018)
6. "Side-Channel Attacks on Implementations of Kyber" (Groot Bruinderink, 2021)
7. STRIDE Threat Model
8. Open Quantum Safe Project Documentation
9. "Secure Memory Handling in Rust" (Rust Security Working Group, 2024)
10. "Best Practices for Key Management Systems" (NIST, 2023)
11. PKCS#11 v2.40: Cryptographic Token Interface Standard
12. "WebAssembly Security Guidelines" (W3C, 2023)
13. "Formal Verification of Cryptographic Implementations" (CryptoVerif, 2023) 