package main

import (
	"fmt"
	"log"
)

func main() {
	fmt.Println("QaSa Cryptography Module")
	fmt.Println("========================")
	fmt.Println()
	fmt.Println("This is a post-quantum cryptography implementation for secure communications.")
	fmt.Println("The module provides:")
	fmt.Println("- CRYSTALS-Kyber for quantum-resistant key encapsulation")
	fmt.Println("- CRYSTALS-Dilithium for quantum-resistant digital signatures")
	fmt.Println("- AES-GCM for symmetric encryption")
	fmt.Println("- Secure key management and storage")
	fmt.Println()
	fmt.Println("For detailed documentation, see:")
	fmt.Println("- ./crypto/README.md - Module overview and structure")
	fmt.Println("- ./crypto/security_review.md - Security analysis and review")
	fmt.Println("- ../docs/api/crypto_api.md - API documentation")
	fmt.Println("- ../docs/api/security_guide.md - Security implementation guide")
	fmt.Println("- ../docs/api/threat_model.md - Threat model analysis")
	fmt.Println()
	fmt.Println("To build the crypto module:")
	fmt.Println("cd crypto && cargo build --release")

	log.Println("Crypto module documentation displayed successfully")
}
