package encryption

import (
	"fmt"
	"sync"
)

var (
	providerInstance CryptoProvider
	providerMutex    sync.Mutex
)

// GetCryptoProvider returns the default crypto provider instance
func GetCryptoProvider() (CryptoProvider, error) {
	providerMutex.Lock()
	defer providerMutex.Unlock()
	
	if providerInstance != nil {
		return providerInstance, nil
	}
	
	// Create a new Rust crypto provider
	provider, err := NewRustCryptoProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto provider: %w", err)
	}
	
	providerInstance = provider
	return provider, nil
}

// SetCryptoProvider sets a custom crypto provider
func SetCryptoProvider(provider CryptoProvider) {
	providerMutex.Lock()
	defer providerMutex.Unlock()
	
	providerInstance = provider
} 