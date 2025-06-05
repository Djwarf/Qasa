package updater

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"crypto/ed25519"
	"encoding/hex"
)

// UpdateInfo represents update information
type UpdateInfo struct {
	Version     string            `json:"version"`
	ReleaseDate time.Time         `json:"release_date"`
	Description string            `json:"description"`
	Critical    bool              `json:"critical"`
	Downloads   map[string]string `json:"downloads"` // platform -> download URL
	Checksums   map[string]string `json:"checksums"` // platform -> SHA256 hash
	Signatures  map[string]string `json:"signatures"` // platform -> signature
	Changes     []string          `json:"changes"`
	Security    SecurityInfo      `json:"security"`
}

// SecurityInfo contains security-related update information
type SecurityInfo struct {
	Fixes         []SecurityFix `json:"fixes"`
	CVEs          []string      `json:"cves"`
	SecurityLevel string        `json:"security_level"` // Low, Medium, High, Critical
}

// SecurityFix represents a security vulnerability fix
type SecurityFix struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Component   string `json:"component"`
}

// Updater manages automatic updates
type Updater struct {
	currentVersion   string
	updateURL        string
	checkInterval    time.Duration
	publicKey        ed25519.PublicKey
	dataDir          string
	executable       string
	channel          chan UpdateInfo
	ctx              context.Context
	cancel           context.CancelFunc
	autoInstall      bool
	verifySignatures bool
}

// UpdaterConfig contains updater configuration
type UpdaterConfig struct {
	CurrentVersion   string
	UpdateURL        string
	CheckInterval    time.Duration
	PublicKey        string // hex-encoded Ed25519 public key
	DataDir          string
	AutoInstall      bool
	VerifySignatures bool
}

// NewUpdater creates a new updater instance
func NewUpdater(ctx context.Context, config UpdaterConfig) (*Updater, error) {
	updaterCtx, cancel := context.WithCancel(ctx)
	
	// Decode public key
	publicKeyBytes, err := hex.DecodeString(config.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", err)
	}
	
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}
	
	// Get current executable path
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %v", err)
	}
	
	updater := &Updater{
		currentVersion:   config.CurrentVersion,
		updateURL:        config.UpdateURL,
		checkInterval:    config.CheckInterval,
		publicKey:        ed25519.PublicKey(publicKeyBytes),
		dataDir:          config.DataDir,
		executable:       executable,
		channel:          make(chan UpdateInfo, 10),
		ctx:              updaterCtx,
		cancel:           cancel,
		autoInstall:      config.AutoInstall,
		verifySignatures: config.VerifySignatures,
	}
	
	return updater, nil
}

// Start begins the automatic update checking
func (u *Updater) Start() {
	log.Printf("Starting automatic updater (current version: %s)", u.currentVersion)
	
	go u.updateLoop()
}

// Stop stops the automatic updater
func (u *Updater) Stop() {
	log.Printf("Stopping automatic updater")
	u.cancel()
}

// GetUpdateChannel returns the channel for update notifications
func (u *Updater) GetUpdateChannel() <-chan UpdateInfo {
	return u.channel
}

// updateLoop runs the periodic update checking
func (u *Updater) updateLoop() {
	ticker := time.NewTicker(u.checkInterval)
	defer ticker.Stop()
	
	// Check immediately on start
	u.checkForUpdates()
	
	for {
		select {
		case <-ticker.C:
			u.checkForUpdates()
		case <-u.ctx.Done():
			return
		}
	}
}

// checkForUpdates checks for available updates
func (u *Updater) checkForUpdates() {
	log.Printf("Checking for updates...")
	
	updateInfo, available, err := u.fetchUpdateInfo()
	if err != nil {
		log.Printf("Failed to check for updates: %v", err)
		return
	}
	
	if !available {
		log.Printf("No updates available")
		return
	}
	
	log.Printf("Update available: version %s", updateInfo.Version)
	
	// Send update notification
	select {
	case u.channel <- *updateInfo:
	default:
		log.Printf("Update channel full, skipping notification")
	}
	
	// Auto-install if enabled and it's a critical update
	if u.autoInstall && updateInfo.Critical {
		log.Printf("Critical update detected, auto-installing...")
		err := u.DownloadAndInstall(*updateInfo)
		if err != nil {
			log.Printf("Auto-install failed: %v", err)
		}
	}
}

// fetchUpdateInfo fetches update information from the server
func (u *Updater) fetchUpdateInfo() (*UpdateInfo, bool, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	req, err := http.NewRequestWithContext(u.ctx, "GET", u.updateURL, nil)
	if err != nil {
		return nil, false, err
	}
	
	// Add headers
	req.Header.Set("User-Agent", fmt.Sprintf("QaSa-Updater/%s (%s-%s)", 
		u.currentVersion, runtime.GOOS, runtime.GOARCH))
	req.Header.Set("X-Current-Version", u.currentVersion)
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	
	var updateInfo UpdateInfo
	err = json.NewDecoder(resp.Body).Decode(&updateInfo)
	if err != nil {
		return nil, false, err
	}
	
	// Check if update is needed
	available := u.isNewerVersion(updateInfo.Version, u.currentVersion)
	
	return &updateInfo, available, nil
}

// isNewerVersion compares version strings
func (u *Updater) isNewerVersion(newVer, currentVer string) bool {
	// Simple semantic version comparison
	// In production, use a proper semver library
	return strings.Compare(newVer, currentVer) > 0
}

// DownloadAndInstall downloads and installs an update
func (u *Updater) DownloadAndInstall(updateInfo UpdateInfo) error {
	platform := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	
	downloadURL, exists := updateInfo.Downloads[platform]
	if !exists {
		return fmt.Errorf("no download available for platform %s", platform)
	}
	
	// Create temporary directory for download
	tempDir, err := os.MkdirTemp(u.dataDir, "qasa-update-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Download the update
	updateFile := filepath.Join(tempDir, "qasa-update")
	log.Printf("Downloading update from %s", downloadURL)
	
	err = u.downloadFile(downloadURL, updateFile)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	
	// Verify checksum
	if u.verifySignatures {
		expectedChecksum, exists := updateInfo.Checksums[platform]
		if !exists {
			return fmt.Errorf("no checksum available for platform %s", platform)
		}
		
		err = u.verifyChecksum(updateFile, expectedChecksum)
		if err != nil {
			return fmt.Errorf("checksum verification failed: %v", err)
		}
		
		// Verify signature
		signature, exists := updateInfo.Signatures[platform]
		if !exists {
			return fmt.Errorf("no signature available for platform %s", platform)
		}
		
		err = u.verifySignature(updateFile, signature)
		if err != nil {
			return fmt.Errorf("signature verification failed: %v", err)
		}
		
		log.Printf("Update verification successful")
	}
	
	// Install the update
	return u.installUpdate(updateFile, updateInfo)
}

// downloadFile downloads a file from a URL
func (u *Updater) downloadFile(url, filepath string) error {
	client := &http.Client{
		Timeout: 5 * time.Minute,
	}
	
	req, err := http.NewRequestWithContext(u.ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}
	
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	
	// Download with progress logging
	size := resp.ContentLength
	downloaded := int64(0)
	
	buffer := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			_, writeErr := out.Write(buffer[:n])
			if writeErr != nil {
				return writeErr
			}
			downloaded += int64(n)
			
			if size > 0 {
				progress := float64(downloaded) / float64(size) * 100
				if downloaded%(1024*1024) == 0 || err == io.EOF { // Log every MB or at end
					log.Printf("Download progress: %.1f%% (%d/%d bytes)", 
						progress, downloaded, size)
				}
			}
		}
		
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	
	log.Printf("Download completed: %d bytes", downloaded)
	return nil
}

// verifyChecksum verifies the SHA256 checksum of a file
func (u *Updater) verifyChecksum(filepath, expectedChecksum string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return err
	}
	
	actualChecksum := fmt.Sprintf("%x", hash.Sum(nil))
	
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", 
			expectedChecksum, actualChecksum)
	}
	
	return nil
}

// verifySignature verifies the Ed25519 signature of a file
func (u *Updater) verifySignature(filepath, signatureHex string) error {
	// Read file content
	content, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}
	
	// Decode signature
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature format: %v", err)
	}
	
	// Verify signature
	valid := ed25519.Verify(u.publicKey, content, signature)
	if !valid {
		return fmt.Errorf("signature verification failed")
	}
	
	return nil
}

// installUpdate installs the downloaded update
func (u *Updater) installUpdate(updateFile string, updateInfo UpdateInfo) error {
	log.Printf("Installing update version %s", updateInfo.Version)
	
	// Make update file executable
	err := os.Chmod(updateFile, 0755)
	if err != nil {
		return fmt.Errorf("failed to make update executable: %v", err)
	}
	
	// Create backup of current executable
	backupPath := u.executable + ".backup"
	err = u.copyFile(u.executable, backupPath)
	if err != nil {
		log.Printf("Warning: failed to create backup: %v", err)
	}
	
	// Replace current executable
	err = u.copyFile(updateFile, u.executable)
	if err != nil {
		// Try to restore backup
		if _, backupErr := os.Stat(backupPath); backupErr == nil {
			os.Rename(backupPath, u.executable)
		}
		return fmt.Errorf("failed to install update: %v", err)
	}
	
	// Remove backup if successful
	os.Remove(backupPath)
	
	log.Printf("Update installed successfully")
	
	// Log security fixes if any
	if len(updateInfo.Security.Fixes) > 0 {
		log.Printf("Security fixes in this update:")
		for _, fix := range updateInfo.Security.Fixes {
			log.Printf("  - %s (%s): %s", fix.ID, fix.Severity, fix.Description)
		}
	}
	
	return nil
}

// copyFile copies a file from src to dst
func (u *Updater) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}
	
	// Copy permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}
	
	return os.Chmod(dst, srcInfo.Mode())
}

// CheckNow forces an immediate update check
func (u *Updater) CheckNow() (*UpdateInfo, bool, error) {
	log.Printf("Manual update check requested")
	return u.fetchUpdateInfo()
}

// GetUpdateHistory returns the update history
func (u *Updater) GetUpdateHistory() ([]UpdateInfo, error) {
	historyFile := filepath.Join(u.dataDir, "update_history.json")
	
	file, err := os.Open(historyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []UpdateInfo{}, nil
		}
		return nil, err
	}
	defer file.Close()
	
	var history []UpdateInfo
	err = json.NewDecoder(file).Decode(&history)
	if err != nil {
		return nil, err
	}
	
	return history, nil
}

// SaveUpdateHistory saves an update to the history
func (u *Updater) SaveUpdateHistory(updateInfo UpdateInfo) error {
	historyFile := filepath.Join(u.dataDir, "update_history.json")
	
	// Load existing history
	history, err := u.GetUpdateHistory()
	if err != nil {
		return err
	}
	
	// Add new update
	history = append(history, updateInfo)
	
	// Keep only last 50 updates
	if len(history) > 50 {
		history = history[len(history)-50:]
	}
	
	// Save updated history
	file, err := os.Create(historyFile)
	if err != nil {
		return err
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(history)
}

// RollbackUpdate attempts to rollback to the previous version
func (u *Updater) RollbackUpdate() error {
	backupPath := u.executable + ".backup"
	
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("no backup available for rollback")
	}
	
	log.Printf("Rolling back to previous version")
	
	// Replace current with backup
	err := u.copyFile(backupPath, u.executable)
	if err != nil {
		return fmt.Errorf("rollback failed: %v", err)
	}
	
	log.Printf("Rollback completed successfully")
	return nil
} 