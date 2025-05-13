package encryption

/*
#cgo LDFLAGS: -L${SRCDIR}/../../crypto/target/release -lqasa_crypto
#include <stdlib.h>
#include "qasa_crypto.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Initialize the Rust crypto library
func initCryptoLib() error {
	var errorMsg *C.char
	defer freeCString(errorMsg)

	result := C.qasa_crypto_init(&errorMsg)
	if result != 0 {
		return fmt.Errorf("failed to initialize crypto library: %s", C.GoString(errorMsg))
	}

	return nil
}

// Helper function to free C strings
func freeCString(str *C.char) {
	if str != nil {
		C.qasa_free_string(str)
	}
}

// KyberVariant defines the security level for Kyber
type KyberVariant int

const (
	// Kyber512 provides NIST security level 1
	Kyber512 KyberVariant = 512
	// Kyber768 provides NIST security level 3 (recommended)
	Kyber768 KyberVariant = 768
	// Kyber1024 provides NIST security level 5
	Kyber1024 KyberVariant = 1024
)

// DilithiumVariant defines the security level for Dilithium
type DilithiumVariant int

const (
	// Dilithium2 provides NIST security level 2
	Dilithium2 DilithiumVariant = 2
	// Dilithium3 provides NIST security level 3 (recommended)
	Dilithium3 DilithiumVariant = 3
	// Dilithium5 provides NIST security level 5
	Dilithium5 DilithiumVariant = 5
)

// kyberKeygen generates a new Kyber key pair
func kyberKeygen(variant KyberVariant) ([]byte, []byte, error) {
	// Allocate buffers for the keys
	const maxPublicKeySize = 1600  // Large enough for all variants
	const maxPrivateKeySize = 3200 // Large enough for all variants

	publicKey := make([]byte, maxPublicKeySize)
	privateKey := make([]byte, maxPrivateKeySize)

	publicKeySize := C.int(maxPublicKeySize)
	privateKeySize := C.int(maxPrivateKeySize)

	var errorMsg *C.char
	defer freeCString(errorMsg)

	result := C.qasa_kyber_keygen(
		C.int(variant),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		&publicKeySize,
		(*C.uint8_t)(unsafe.Pointer(&privateKey[0])),
		&privateKeySize,
		&errorMsg,
	)

	if result != 0 {
		return nil, nil, fmt.Errorf("kyber key generation failed: %s", C.GoString(errorMsg))
	}

	// Resize the slices to the actual key sizes
	publicKey = publicKey[:publicKeySize]
	privateKey = privateKey[:privateKeySize]

	return publicKey, privateKey, nil
}

// kyberEncapsulate generates and encapsulates a shared secret using a Kyber public key
func kyberEncapsulate(variant KyberVariant, publicKey []byte) ([]byte, []byte, error) {
	// Allocate buffers for the ciphertext and shared secret
	const maxCiphertextSize = 1600 // Large enough for all variants
	const sharedSecretSize = 32    // Fixed for all variants

	ciphertext := make([]byte, maxCiphertextSize)
	sharedSecret := make([]byte, sharedSecretSize)

	ciphertextSize := C.int(maxCiphertextSize)
	ssSize := C.int(sharedSecretSize)

	var errorMsg *C.char
	defer freeCString(errorMsg)

	result := C.qasa_kyber_encapsulate(
		C.int(variant),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		C.int(len(publicKey)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		&ciphertextSize,
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])),
		&ssSize,
		&errorMsg,
	)

	if result != 0 {
		return nil, nil, fmt.Errorf("kyber encapsulation failed: %s", C.GoString(errorMsg))
	}

	// Resize the ciphertext to its actual size
	ciphertext = ciphertext[:ciphertextSize]
	sharedSecret = sharedSecret[:ssSize]

	return ciphertext, sharedSecret, nil
}

// kyberDecapsulate decapsulates a shared secret using a Kyber private key and ciphertext
func kyberDecapsulate(variant KyberVariant, privateKey []byte, ciphertext []byte) ([]byte, error) {
	// Allocate buffer for the shared secret
	const sharedSecretSize = 32 // Fixed for all variants

	sharedSecret := make([]byte, sharedSecretSize)
	ssSize := C.int(sharedSecretSize)

	var errorMsg *C.char
	defer freeCString(errorMsg)

	result := C.qasa_kyber_decapsulate(
		C.int(variant),
		(*C.uint8_t)(unsafe.Pointer(&privateKey[0])),
		C.int(len(privateKey)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		C.int(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])),
		&ssSize,
		&errorMsg,
	)

	if result != 0 {
		return nil, fmt.Errorf("kyber decapsulation failed: %s", C.GoString(errorMsg))
	}

	// Resize the shared secret to its actual size
	sharedSecret = sharedSecret[:ssSize]

	return sharedSecret, nil
}

// dilithiumKeygen generates a new Dilithium key pair
func dilithiumKeygen(variant DilithiumVariant) ([]byte, []byte, error) {
	// Allocate buffers for the keys
	const maxPublicKeySize = 2600  // Large enough for all variants
	const maxPrivateKeySize = 5000 // Large enough for all variants

	publicKey := make([]byte, maxPublicKeySize)
	privateKey := make([]byte, maxPrivateKeySize)

	publicKeySize := C.int(maxPublicKeySize)
	privateKeySize := C.int(maxPrivateKeySize)

	var errorMsg *C.char
	defer freeCString(errorMsg)

	result := C.qasa_dilithium_keygen(
		C.int(variant),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		&publicKeySize,
		(*C.uint8_t)(unsafe.Pointer(&privateKey[0])),
		&privateKeySize,
		&errorMsg,
	)

	if result != 0 {
		return nil, nil, fmt.Errorf("dilithium key generation failed: %s", C.GoString(errorMsg))
	}

	// Resize the slices to the actual key sizes
	publicKey = publicKey[:publicKeySize]
	privateKey = privateKey[:privateKeySize]

	return publicKey, privateKey, nil
}

// dilithiumSign signs a message using a Dilithium private key
func dilithiumSign(variant DilithiumVariant, privateKey []byte, message []byte) ([]byte, error) {
	// Allocate buffer for the signature
	const maxSignatureSize = 5000 // Large enough for all variants

	signature := make([]byte, maxSignatureSize)
	signatureSize := C.int(maxSignatureSize)

	var errorMsg *C.char
	defer freeCString(errorMsg)

	result := C.qasa_dilithium_sign(
		C.int(variant),
		(*C.uint8_t)(unsafe.Pointer(&privateKey[0])),
		C.int(len(privateKey)),
		(*C.uint8_t)(unsafe.Pointer(&message[0])),
		C.int(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&signature[0])),
		&signatureSize,
		&errorMsg,
	)

	if result != 0 {
		return nil, fmt.Errorf("dilithium signing failed: %s", C.GoString(errorMsg))
	}

	// Resize the signature to its actual size
	signature = signature[:signatureSize]

	return signature, nil
}

// dilithiumVerify verifies a message signature using a Dilithium public key
func dilithiumVerify(variant DilithiumVariant, publicKey []byte, message []byte, signature []byte) (bool, error) {
	var errorMsg *C.char
	defer freeCString(errorMsg)

	result := C.qasa_dilithium_verify(
		C.int(variant),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		C.int(len(publicKey)),
		(*C.uint8_t)(unsafe.Pointer(&message[0])),
		C.int(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&signature[0])),
		C.int(len(signature)),
		&errorMsg,
	)

	if result < 0 {
		return false, fmt.Errorf("dilithium verification failed: %s", C.GoString(errorMsg))
	}

	// result is 1 for valid signatures, 0 for invalid ones
	return result == 1, nil
}

// aesGcmEncrypt encrypts data using AES-GCM
func aesGcmEncrypt(key []byte, plaintext []byte, associatedData []byte) ([]byte, []byte, error) {
	// AES-256-GCM requires a 32-byte key
	if len(key) != 32 {
		return nil, nil, errors.New("AES-GCM encryption requires a 32-byte key")
	}

	// Allocate buffers for the ciphertext and nonce
	ciphertext := make([]byte, len(plaintext)+16) // Plaintext + max auth tag size
	nonce := make([]byte, 12)                      // Fixed nonce size for AES-GCM

	ciphertextSize := C.int(len(ciphertext))
	nonceSize := C.int(len(nonce))

	// Handle nil associatedData
	var aadPtr *C.uint8_t
	aadSize := C.int(0)
	if len(associatedData) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&associatedData[0]))
		aadSize = C.int(len(associatedData))
	}

	var errorMsg *C.char
	defer freeCString(errorMsg)

	result := C.qasa_aes_gcm_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		C.int(len(key)),
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])),
		C.int(len(plaintext)),
		aadPtr,
		aadSize,
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		&ciphertextSize,
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		&nonceSize,
		&errorMsg,
	)

	if result != 0 {
		return nil, nil, fmt.Errorf("AES-GCM encryption failed: %s", C.GoString(errorMsg))
	}

	// Resize the ciphertext and nonce to their actual sizes
	ciphertext = ciphertext[:ciphertextSize]
	nonce = nonce[:nonceSize]

	return ciphertext, nonce, nil
}

// aesGcmDecrypt decrypts data using AES-GCM
func aesGcmDecrypt(key []byte, ciphertext []byte, nonce []byte, associatedData []byte) ([]byte, error) {
	// AES-256-GCM requires a 32-byte key
	if len(key) != 32 {
		return nil, errors.New("AES-GCM decryption requires a 32-byte key")
	}

	// Allocate buffer for the plaintext
	plaintext := make([]byte, len(ciphertext)) // Ciphertext includes auth tag
	plaintextSize := C.int(len(plaintext))

	// Handle nil associatedData
	var aadPtr *C.uint8_t
	aadSize := C.int(0)
	if len(associatedData) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&associatedData[0]))
		aadSize = C.int(len(associatedData))
	}

	var errorMsg *C.char
	defer freeCString(errorMsg)

	result := C.qasa_aes_gcm_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		C.int(len(key)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		C.int(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		C.int(len(nonce)),
		aadPtr,
		aadSize,
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])),
		&plaintextSize,
		&errorMsg,
	)

	if result != 0 {
		return nil, fmt.Errorf("AES-GCM decryption failed: %s", C.GoString(errorMsg))
	}

	// Resize the plaintext to its actual size
	plaintext = plaintext[:plaintextSize]

	return plaintext, nil
}

// Ensure the crypto library is initialized when the package is imported
func init() {
	runtime.LockOSThread()
	err := initCryptoLib()
	runtime.UnlockOSThread()
	if err != nil {
		// Log the error but don't fail, as the library might be initialized later
		fmt.Printf("Warning: Failed to initialize crypto library: %s\n", err)
	}
} 