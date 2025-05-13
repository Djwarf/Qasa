package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/multiformats/go-multiaddr"
)

// DefaultBootstrapNodes is a list of well-known public nodes that can help bootstrap the network
var DefaultBootstrapNodes = []string{
	// Add some public bootstrap nodes here when available
	// For testing, we'll use empty defaults
}

// BootstrapNodesFile is the name of the file to store custom bootstrap nodes
const BootstrapNodesFile = "bootstrap_nodes.json"

// BootstrapNodeInfo represents information about a bootstrap node
type BootstrapNodeInfo struct {
	Address    string    `json:"address"`
	LastSeen   time.Time `json:"last_seen"`
	Successful int       `json:"successful_connects"`
	Failed     int       `json:"failed_connects"`
}

// BootstrapNodeList manages a list of bootstrap nodes
type BootstrapNodeList struct {
	Nodes       map[string]*BootstrapNodeInfo `json:"nodes"`
	configDir   string
	configPath  string
	initialized bool
}

// NewBootstrapNodeList creates a new bootstrap node list
func NewBootstrapNodeList(configDir string) (*BootstrapNodeList, error) {
	bnl := &BootstrapNodeList{
		Nodes:     make(map[string]*BootstrapNodeInfo),
		configDir: configDir,
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	bnl.configPath = filepath.Join(configDir, BootstrapNodesFile)

	// Try to load existing bootstrap nodes
	if err := bnl.Load(); err != nil {
		// If file doesn't exist, initialize with defaults
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load bootstrap nodes: %w", err)
		}
		
		// Initialize with default bootstrap nodes
		for _, addr := range DefaultBootstrapNodes {
			if err := bnl.AddNode(addr); err != nil {
				fmt.Printf("Warning: invalid default bootstrap node %s: %s\n", addr, err)
			}
		}
		
		// Save the default nodes
		if err := bnl.Save(); err != nil {
			return nil, fmt.Errorf("failed to save bootstrap nodes: %w", err)
		}
	}

	bnl.initialized = true
	return bnl, nil
}

// Load loads bootstrap nodes from the configuration file
func (bnl *BootstrapNodeList) Load() error {
	data, err := os.ReadFile(bnl.configPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, bnl)
}

// Save saves the bootstrap nodes to the configuration file
func (bnl *BootstrapNodeList) Save() error {
	data, err := json.MarshalIndent(bnl, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal bootstrap nodes: %w", err)
	}

	return os.WriteFile(bnl.configPath, data, 0644)
}

// AddNode adds a new bootstrap node to the list
func (bnl *BootstrapNodeList) AddNode(address string) error {
	// Validate the multiaddress
	_, err := multiaddr.NewMultiaddr(address)
	if err != nil {
		return fmt.Errorf("invalid multiaddress: %w", err)
	}

	// Check if it already exists
	if _, exists := bnl.Nodes[address]; !exists {
		bnl.Nodes[address] = &BootstrapNodeInfo{
			Address:    address,
			LastSeen:   time.Time{}, // Zero time
			Successful: 0,
			Failed:     0,
		}
	}

	// Save if already initialized
	if bnl.initialized {
		return bnl.Save()
	}
	
	return nil
}

// RemoveNode removes a bootstrap node from the list
func (bnl *BootstrapNodeList) RemoveNode(address string) error {
	delete(bnl.Nodes, address)
	
	// Save if already initialized
	if bnl.initialized {
		return bnl.Save()
	}
	
	return nil
}

// GetNodes returns all bootstrap nodes as multiaddresses
func (bnl *BootstrapNodeList) GetNodes() ([]multiaddr.Multiaddr, error) {
	var addrs []multiaddr.Multiaddr
	
	for address := range bnl.Nodes {
		addr, err := multiaddr.NewMultiaddr(address)
		if err != nil {
			return nil, fmt.Errorf("invalid stored multiaddress %s: %w", address, err)
		}
		addrs = append(addrs, addr)
	}
	
	return addrs, nil
}

// RecordSuccess records a successful connection to a bootstrap node
func (bnl *BootstrapNodeList) RecordSuccess(address string) error {
	node, exists := bnl.Nodes[address]
	if !exists {
		return fmt.Errorf("bootstrap node not found: %s", address)
	}
	
	node.LastSeen = time.Now()
	node.Successful++
	
	return bnl.Save()
}

// RecordFailure records a failed connection to a bootstrap node
func (bnl *BootstrapNodeList) RecordFailure(address string) error {
	node, exists := bnl.Nodes[address]
	if !exists {
		return fmt.Errorf("bootstrap node not found: %s", address)
	}
	
	node.Failed++
	
	return bnl.Save()
}

// GetBestNodes returns the most reliable bootstrap nodes
func (bnl *BootstrapNodeList) GetBestNodes(limit int) ([]multiaddr.Multiaddr, error) {
	// First, get all nodes
	allNodes, err := bnl.GetNodes()
	if err != nil {
		return nil, err
	}
	
	// If we have fewer nodes than the limit, return them all
	if len(allNodes) <= limit {
		return allNodes, nil
	}
	
	// TODO: Implement a more sophisticated selection algorithm based on
	// success rate, last seen time, etc.
	
	// For now, just return the first 'limit' nodes
	return allNodes[:limit], nil
} 