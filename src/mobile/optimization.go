package mobile

import (
	"context"
	"runtime"
	"sync"
	"time"
	"log"
	"runtime/debug"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/battery"
)

// MobileOptimizer manages resource optimization for mobile devices
type MobileOptimizer struct {
	ctx           context.Context
	cancel        context.CancelFunc
	config        *OptimizationConfig
	metrics       *PerformanceMetrics
	batteryLevel  float64
	isCharging    bool
	memoryUsage   uint64
	cpuUsage      float64
	networkMode   NetworkMode
	powerMode     PowerMode
	mu            sync.RWMutex
}

// OptimizationConfig contains mobile optimization settings
type OptimizationConfig struct {
	BatteryThresholds   BatteryThresholds   `json:"battery_thresholds"`
	MemoryLimits        MemoryLimits        `json:"memory_limits"`
	CPULimits           CPULimits           `json:"cpu_limits"`
	NetworkSettings     NetworkSettings     `json:"network_settings"`
	BackgroundBehavior  BackgroundBehavior  `json:"background_behavior"`
	CryptoOptimizations CryptoOptimizations `json:"crypto_optimizations"`
}

// BatteryThresholds defines battery level thresholds for optimization
type BatteryThresholds struct {
	Critical float64 `json:"critical"` // Below this, enter ultra power save
	Low      float64 `json:"low"`      // Below this, enter power save mode
	Normal   float64 `json:"normal"`   // Above this, normal operation
}

// MemoryLimits defines memory usage limits
type MemoryLimits struct {
	MaxHeapSize     uint64 `json:"max_heap_size"`
	GCTargetPercent int    `json:"gc_target_percent"`
	MaxConnections  int    `json:"max_connections"`
	MessageBuffer   int    `json:"message_buffer"`
}

// CPULimits defines CPU usage optimization
type CPULimits struct {
	MaxGoroutines   int           `json:"max_goroutines"`
	ProcessInterval time.Duration `json:"process_interval"`
	ThrottleAt      float64       `json:"throttle_at"`
}

// NetworkSettings for mobile network optimization
type NetworkSettings struct {
	WiFiPreferred       bool          `json:"wifi_preferred"`
	CellularDataLimit   uint64        `json:"cellular_data_limit"`
	CompressionEnabled  bool          `json:"compression_enabled"`
	KeepAliveInterval   time.Duration `json:"keep_alive_interval"`
	ConnectionTimeout   time.Duration `json:"connection_timeout"`
	RetryBackoff        time.Duration `json:"retry_backoff"`
}

// BackgroundBehavior defines how the app behaves in background
type BackgroundBehavior struct {
	ReduceActivity    bool          `json:"reduce_activity"`
	PauseDiscovery    bool          `json:"pause_discovery"`
	MessageQueueOnly  bool          `json:"message_queue_only"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
}

// CryptoOptimizations for mobile crypto operations
type CryptoOptimizations struct {
	UseHardwareAccel     bool `json:"use_hardware_accel"`
	PrecomputeKeys       bool `json:"precompute_keys"`
	BatchOperations      bool `json:"batch_operations"`
	ReduceKeyGeneration  bool `json:"reduce_key_generation"`
}

// PerformanceMetrics tracks mobile performance
type PerformanceMetrics struct {
	StartTime          time.Time     `json:"start_time"`
	LastUpdate         time.Time     `json:"last_update"`
	BatteryUsage       float64       `json:"battery_usage"`
	MemoryPeak         uint64        `json:"memory_peak"`
	CPUTime            time.Duration `json:"cpu_time"`
	NetworkDataUsed    uint64        `json:"network_data_used"`
	MessagesSent       uint64        `json:"messages_sent"`
	MessagesReceived   uint64        `json:"messages_received"`
	CryptoOperations   uint64        `json:"crypto_operations"`
	GoroutineCount     int           `json:"goroutine_count"`
	GCCount            uint32        `json:"gc_count"`
	PowerModeChanges   int           `json:"power_mode_changes"`
	NetworkSwitches    int           `json:"network_switches"`
	mu                 sync.RWMutex
}

// NetworkMode represents the type of network connection
type NetworkMode int

const (
	WiFi NetworkMode = iota
	Cellular
	Offline
)

// PowerMode represents the current power optimization mode
type PowerMode int

const (
	NormalPower PowerMode = iota
	PowerSave
	UltraPowerSave
)

// NewMobileOptimizer creates a new mobile optimizer
func NewMobileOptimizer(ctx context.Context, config *OptimizationConfig) *MobileOptimizer {
	optimizerCtx, cancel := context.WithCancel(ctx)
	
	if config == nil {
		config = DefaultOptimizationConfig()
	}
	
	optimizer := &MobileOptimizer{
		ctx:     optimizerCtx,
		cancel:  cancel,
		config:  config,
		metrics: NewPerformanceMetrics(),
		powerMode: NormalPower,
		networkMode: WiFi,
	}
	
	return optimizer
}

// DefaultOptimizationConfig returns default mobile optimization settings
func DefaultOptimizationConfig() *OptimizationConfig {
	return &OptimizationConfig{
		BatteryThresholds: BatteryThresholds{
			Critical: 10.0,
			Low:      25.0,
			Normal:   50.0,
		},
		MemoryLimits: MemoryLimits{
			MaxHeapSize:     100 * 1024 * 1024, // 100MB
			GCTargetPercent: 50,
			MaxConnections:  10,
			MessageBuffer:   100,
		},
		CPULimits: CPULimits{
			MaxGoroutines:   50,
			ProcessInterval: 100 * time.Millisecond,
			ThrottleAt:      80.0,
		},
		NetworkSettings: NetworkSettings{
			WiFiPreferred:       true,
			CellularDataLimit:   50 * 1024 * 1024, // 50MB
			CompressionEnabled:  true,
			KeepAliveInterval:   30 * time.Second,
			ConnectionTimeout:   10 * time.Second,
			RetryBackoff:        5 * time.Second,
		},
		BackgroundBehavior: BackgroundBehavior{
			ReduceActivity:    true,
			PauseDiscovery:    true,
			MessageQueueOnly:  true,
			HeartbeatInterval: 60 * time.Second,
		},
		CryptoOptimizations: CryptoOptimizations{
			UseHardwareAccel:    true,
			PrecomputeKeys:      true,
			BatchOperations:     true,
			ReduceKeyGeneration: true,
		},
	}
}

// NewPerformanceMetrics creates a new performance metrics tracker
func NewPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{
		StartTime:  time.Now(),
		LastUpdate: time.Now(),
	}
}

// Start begins mobile optimization monitoring
func (mo *MobileOptimizer) Start() error {
	log.Printf("Starting mobile optimizer")
	
	// Set initial memory settings
	mo.applyMemoryOptimizations()
	
	// Start monitoring goroutines
	go mo.monitorResources()
	go mo.monitorBattery()
	go mo.optimizeMemory()
	go mo.managePowerMode()
	
	return nil
}

// Stop stops the mobile optimizer
func (mo *MobileOptimizer) Stop() {
	log.Printf("Stopping mobile optimizer")
	mo.cancel()
}

// monitorResources monitors system resources
func (mo *MobileOptimizer) monitorResources() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			mo.updateResourceMetrics()
		case <-mo.ctx.Done():
			return
		}
	}
}

// updateResourceMetrics updates current resource usage metrics
func (mo *MobileOptimizer) updateResourceMetrics() {
	// Update memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	mo.mu.Lock()
	mo.memoryUsage = memStats.Alloc
	if mo.memoryUsage > mo.metrics.MemoryPeak {
		mo.metrics.MemoryPeak = mo.memoryUsage
	}
	mo.metrics.GoroutineCount = runtime.NumGoroutine()
	mo.metrics.GCCount = memStats.NumGC
	mo.metrics.LastUpdate = time.Now()
	mo.mu.Unlock()
	
	// Update CPU usage
	if cpuPercent, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercent) > 0 {
		mo.mu.Lock()
		mo.cpuUsage = cpuPercent[0]
		mo.mu.Unlock()
	}
	
	// Check if throttling is needed
	mo.checkResourceThrottling()
}

// monitorBattery monitors battery status
func (mo *MobileOptimizer) monitorBattery() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			mo.updateBatteryStatus()
		case <-mo.ctx.Done():
			return
		}
	}
}

// updateBatteryStatus updates battery level and charging status
func (mo *MobileOptimizer) updateBatteryStatus() {
	batteries, err := battery.GetAll()
	if err != nil || len(batteries) == 0 {
		return
	}
	
	bat := batteries[0]
	
	mo.mu.Lock()
	oldLevel := mo.batteryLevel
	mo.batteryLevel = bat.Current / bat.Full * 100
	mo.isCharging = bat.State == battery.Charging
	mo.mu.Unlock()
	
	// Calculate battery usage rate
	if oldLevel > 0 {
		mo.metrics.mu.Lock()
		mo.metrics.BatteryUsage = oldLevel - mo.batteryLevel
		mo.metrics.mu.Unlock()
	}
	
	log.Printf("Battery: %.1f%% (charging: %v)", mo.batteryLevel, mo.isCharging)
}

// checkResourceThrottling checks if resource throttling is needed
func (mo *MobileOptimizer) checkResourceThrottling() {
	mo.mu.RLock()
	memUsage := mo.memoryUsage
	cpuUsage := mo.cpuUsage
	goroutines := mo.metrics.GoroutineCount
	mo.mu.RUnlock()
	
	// Memory throttling
	if memUsage > mo.config.MemoryLimits.MaxHeapSize {
		log.Printf("Memory usage high: %d bytes, forcing GC", memUsage)
		runtime.GC()
		debug.FreeOSMemory()
	}
	
	// Goroutine throttling
	if goroutines > mo.config.CPULimits.MaxGoroutines {
		log.Printf("Too many goroutines: %d, throttling", goroutines)
		// In a real implementation, you'd throttle new goroutine creation
	}
	
	// CPU throttling
	if cpuUsage > mo.config.CPULimits.ThrottleAt {
		log.Printf("High CPU usage: %.1f%%, throttling", cpuUsage)
		// Add delays to reduce CPU usage
		time.Sleep(mo.config.CPULimits.ProcessInterval)
	}
}

// optimizeMemory runs periodic memory optimization
func (mo *MobileOptimizer) optimizeMemory() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			mo.performMemoryOptimization()
		case <-mo.ctx.Done():
			return
		}
	}
}

// performMemoryOptimization performs memory cleanup
func (mo *MobileOptimizer) performMemoryOptimization() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	// Force GC if memory usage is high
	if memStats.Alloc > mo.config.MemoryLimits.MaxHeapSize {
		runtime.GC()
		debug.FreeOSMemory()
		log.Printf("Performed memory cleanup: %d -> %d bytes", 
			memStats.Alloc, getMemoryUsage())
	}
}

// managePowerMode manages power optimization modes
func (mo *MobileOptimizer) managePowerMode() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			mo.adjustPowerMode()
		case <-mo.ctx.Done():
			return
		}
	}
}

// adjustPowerMode adjusts power mode based on battery level
func (mo *MobileOptimizer) adjustPowerMode() {
	mo.mu.RLock()
	batteryLevel := mo.batteryLevel
	isCharging := mo.isCharging
	oldMode := mo.powerMode
	mo.mu.RUnlock()
	
	var newMode PowerMode
	
	if isCharging || batteryLevel > mo.config.BatteryThresholds.Normal {
		newMode = NormalPower
	} else if batteryLevel > mo.config.BatteryThresholds.Low {
		newMode = PowerSave
	} else {
		newMode = UltraPowerSave
	}
	
	if newMode != oldMode {
		mo.mu.Lock()
		mo.powerMode = newMode
		mo.metrics.PowerModeChanges++
		mo.mu.Unlock()
		
		mo.applyPowerMode(newMode)
		log.Printf("Power mode changed: %v -> %v (battery: %.1f%%)", 
			oldMode, newMode, batteryLevel)
	}
}

// applyPowerMode applies the specified power mode optimizations
func (mo *MobileOptimizer) applyPowerMode(mode PowerMode) {
	switch mode {
	case NormalPower:
		mo.applyNormalPowerMode()
	case PowerSave:
		mo.applyPowerSaveMode()
	case UltraPowerSave:
		mo.applyUltraPowerSaveMode()
	}
}

// applyNormalPowerMode applies normal power settings
func (mo *MobileOptimizer) applyNormalPowerMode() {
	debug.SetGCPercent(100) // Default GC target
	// Enable all features
	log.Printf("Applied normal power mode")
}

// applyPowerSaveMode applies power save optimizations
func (mo *MobileOptimizer) applyPowerSaveMode() {
	debug.SetGCPercent(mo.config.MemoryLimits.GCTargetPercent)
	// Reduce background activity
	// Increase message batching
	log.Printf("Applied power save mode")
}

// applyUltraPowerSaveMode applies ultra power save optimizations
func (mo *MobileOptimizer) applyUltraPowerSaveMode() {
	debug.SetGCPercent(25) // More aggressive GC
	// Minimize all operations
	// Queue messages for later
	log.Printf("Applied ultra power save mode")
}

// applyMemoryOptimizations applies memory optimization settings
func (mo *MobileOptimizer) applyMemoryOptimizations() {
	debug.SetGCPercent(mo.config.MemoryLimits.GCTargetPercent)
	debug.SetMemoryLimit(int64(mo.config.MemoryLimits.MaxHeapSize))
}

// OptimizeForBackground optimizes when app goes to background
func (mo *MobileOptimizer) OptimizeForBackground() {
	log.Printf("Optimizing for background mode")
	
	if mo.config.BackgroundBehavior.ReduceActivity {
		// Reduce network activity
		// Pause non-essential services
	}
	
	if mo.config.BackgroundBehavior.PauseDiscovery {
		// Pause peer discovery
	}
	
	// Force garbage collection
	runtime.GC()
	debug.FreeOSMemory()
}

// OptimizeForForeground optimizes when app comes to foreground
func (mo *MobileOptimizer) OptimizeForForeground() {
	log.Printf("Optimizing for foreground mode")
	
	// Resume all services
	// Restore normal operation
}

// GetMetrics returns current performance metrics
func (mo *MobileOptimizer) GetMetrics() *PerformanceMetrics {
	mo.metrics.mu.RLock()
	defer mo.metrics.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	metrics := *mo.metrics
	return &metrics
}

// GetBatteryLevel returns current battery level
func (mo *MobileOptimizer) GetBatteryLevel() float64 {
	mo.mu.RLock()
	defer mo.mu.RUnlock()
	return mo.batteryLevel
}

// GetPowerMode returns current power mode
func (mo *MobileOptimizer) GetPowerMode() PowerMode {
	mo.mu.RLock()
	defer mo.mu.RUnlock()
	return mo.powerMode
}

// GetMemoryUsage returns current memory usage
func (mo *MobileOptimizer) GetMemoryUsage() uint64 {
	mo.mu.RLock()
	defer mo.mu.RUnlock()
	return mo.memoryUsage
}

// ShouldThrottle returns whether operations should be throttled
func (mo *MobileOptimizer) ShouldThrottle() bool {
	mo.mu.RLock()
	defer mo.mu.RUnlock()
	
	return mo.powerMode == UltraPowerSave || 
		   mo.cpuUsage > mo.config.CPULimits.ThrottleAt ||
		   mo.memoryUsage > mo.config.MemoryLimits.MaxHeapSize
}

// OptimizeNetworkUsage optimizes network usage based on connection type
func (mo *MobileOptimizer) OptimizeNetworkUsage(connectionType NetworkMode) {
	mo.mu.Lock()
	oldMode := mo.networkMode
	mo.networkMode = connectionType
	if oldMode != connectionType {
		mo.metrics.NetworkSwitches++
	}
	mo.mu.Unlock()
	
	switch connectionType {
	case WiFi:
		log.Printf("Optimizing for WiFi connection")
		// Enable full features, larger message sizes
		
	case Cellular:
		log.Printf("Optimizing for cellular connection")
		// Enable compression, reduce message sizes
		// Monitor data usage
		
	case Offline:
		log.Printf("Optimizing for offline mode")
		// Queue messages, pause non-essential operations
	}
}

// IncrementCryptoOperations increments the crypto operations counter
func (mo *MobileOptimizer) IncrementCryptoOperations() {
	mo.metrics.mu.Lock()
	mo.metrics.CryptoOperations++
	mo.metrics.mu.Unlock()
}

// IncrementMessageCount increments message counters
func (mo *MobileOptimizer) IncrementMessageCount(sent bool) {
	mo.metrics.mu.Lock()
	if sent {
		mo.metrics.MessagesSent++
	} else {
		mo.metrics.MessagesReceived++
	}
	mo.metrics.mu.Unlock()
}

// AddNetworkDataUsage adds to the network data usage counter
func (mo *MobileOptimizer) AddNetworkDataUsage(bytes uint64) {
	mo.metrics.mu.Lock()
	mo.metrics.NetworkDataUsed += bytes
	mo.metrics.mu.Unlock()
}

// getMemoryUsage returns current memory usage
func getMemoryUsage() uint64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return memStats.Alloc
}

// String methods for enums
func (nm NetworkMode) String() string {
	switch nm {
	case WiFi:
		return "WiFi"
	case Cellular:
		return "Cellular"
	case Offline:
		return "Offline"
	default:
		return "Unknown"
	}
}

func (pm PowerMode) String() string {
	switch pm {
	case NormalPower:
		return "Normal"
	case PowerSave:
		return "PowerSave"
	case UltraPowerSave:
		return "UltraPowerSave"
	default:
		return "Unknown"
	}
} 