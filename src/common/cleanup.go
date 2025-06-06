package common

import (
	"log"
	"sync"
	"time"
)

// CleanupManager manages cleanup tasks for expired resources
type CleanupManager struct {
	tasks   map[string]*CleanupTask
	mutex   sync.RWMutex
	ticker  *time.Ticker
	done    chan bool
	running bool
}

// CleanupTask represents a cleanup task
type CleanupTask struct {
	Name     string
	Interval time.Duration
	Cleanup  func() int // Returns number of items cleaned
	LastRun  time.Time
}

// CleanupFunc defines the signature for cleanup functions
type CleanupFunc func() int

// NewCleanupManager creates a new cleanup manager
func NewCleanupManager(interval time.Duration) *CleanupManager {
	if interval <= 0 {
		interval = 5 * time.Minute // Default cleanup interval
	}
	
	return &CleanupManager{
		tasks:  make(map[string]*CleanupTask),
		ticker: time.NewTicker(interval),
		done:   make(chan bool),
	}
}

// AddTask adds a cleanup task
func (cm *CleanupManager) AddTask(name string, interval time.Duration, cleanup CleanupFunc) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	cm.tasks[name] = &CleanupTask{
		Name:     name,
		Interval: interval,
		Cleanup:  cleanup,
		LastRun:  time.Now(),
	}
}

// RemoveTask removes a cleanup task
func (cm *CleanupManager) RemoveTask(name string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	delete(cm.tasks, name)
}

// Start starts the cleanup manager
func (cm *CleanupManager) Start() {
	cm.mutex.Lock()
	if cm.running {
		cm.mutex.Unlock()
		return
	}
	cm.running = true
	cm.mutex.Unlock()
	
	go cm.run()
}

// Stop stops the cleanup manager
func (cm *CleanupManager) Stop() {
	cm.mutex.Lock()
	if !cm.running {
		cm.mutex.Unlock()
		return
	}
	cm.running = false
	cm.mutex.Unlock()
	
	cm.done <- true
	cm.ticker.Stop()
}

// run executes the cleanup loop
func (cm *CleanupManager) run() {
	for {
		select {
		case <-cm.ticker.C:
			cm.runCleanupTasks()
		case <-cm.done:
			return
		}
	}
}

// runCleanupTasks runs all cleanup tasks that are due
func (cm *CleanupManager) runCleanupTasks() {
	cm.mutex.RLock()
	tasks := make([]*CleanupTask, 0, len(cm.tasks))
	for _, task := range cm.tasks {
		tasks = append(tasks, task)
	}
	cm.mutex.RUnlock()
	
	now := time.Now()
	for _, task := range tasks {
		if now.Sub(task.LastRun) >= task.Interval {
			go cm.executeTask(task, now)
		}
	}
}

// executeTask executes a single cleanup task
func (cm *CleanupManager) executeTask(task *CleanupTask, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Cleanup task %s panicked: %v", task.Name, r)
		}
	}()
	
	start := time.Now()
	cleaned := task.Cleanup()
	duration := time.Since(start)
	
	cm.mutex.Lock()
	task.LastRun = now
	cm.mutex.Unlock()
	
	if cleaned > 0 {
		log.Printf("Cleanup task %s cleaned %d items in %v", task.Name, cleaned, duration)
	}
}

// RunNow immediately runs all cleanup tasks
func (cm *CleanupManager) RunNow() {
	cm.runCleanupTasks()
}

// GetStats returns cleanup statistics
func (cm *CleanupManager) GetStats() map[string]CleanupStats {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	stats := make(map[string]CleanupStats)
	for name, task := range cm.tasks {
		stats[name] = CleanupStats{
			Name:        name,
			Interval:    task.Interval,
			LastRun:     task.LastRun,
			NextRun:     task.LastRun.Add(task.Interval),
			IsOverdue:   time.Since(task.LastRun) > task.Interval,
		}
	}
	return stats
}

// CleanupStats represents statistics for a cleanup task
type CleanupStats struct {
	Name      string        `json:"name"`
	Interval  time.Duration `json:"interval"`
	LastRun   time.Time     `json:"last_run"`
	NextRun   time.Time     `json:"next_run"`
	IsOverdue bool          `json:"is_overdue"`
}

// Common cleanup patterns

// ExpiredItemsCleanup creates a cleanup function for expired items
func ExpiredItemsCleanup[T any](
	items map[string]T,
	mutex sync.Locker,
	isExpired func(T) bool,
	onRemove func(string, T),
) CleanupFunc {
	return func() int {
		mutex.Lock()
		defer mutex.Unlock()
		
		removed := 0
		for key, item := range items {
			if isExpired(item) {
				if onRemove != nil {
					onRemove(key, item)
				}
				delete(items, key)
				removed++
			}
		}
		return removed
	}
}

// TimestampExpiredCleanup creates a cleanup function for items with timestamps
func TimestampExpiredCleanup[T interface{ GetTimestamp() time.Time }](
	items map[string]T,
	mutex sync.Locker,
	maxAge time.Duration,
	onRemove func(string, T),
) CleanupFunc {
	return ExpiredItemsCleanup(items, mutex, func(item T) bool {
		return time.Since(item.GetTimestamp()) > maxAge
	}, onRemove)
}

// FileCleanup creates a cleanup function for files
func FileCleanup(
	getFiles func() []string,
	isExpired func(string) bool,
	removeFile func(string) error,
) CleanupFunc {
	return func() int {
		files := getFiles()
		removed := 0
		
		for _, file := range files {
			if isExpired(file) {
				if err := removeFile(file); err == nil {
					removed++
				}
			}
		}
		return removed
	}
}

// Global cleanup manager
var globalCleanupManager *CleanupManager
var globalCleanupOnce sync.Once

// GetGlobalCleanupManager returns the global cleanup manager
func GetGlobalCleanupManager() *CleanupManager {
	globalCleanupOnce.Do(func() {
		globalCleanupManager = NewCleanupManager(5 * time.Minute)
		globalCleanupManager.Start()
	})
	return globalCleanupManager
}

// Convenience functions for global cleanup manager

// RegisterCleanupTask registers a cleanup task with the global manager
func RegisterCleanupTask(name string, interval time.Duration, cleanup CleanupFunc) {
	GetGlobalCleanupManager().AddTask(name, interval, cleanup)
}

// UnregisterCleanupTask removes a cleanup task from the global manager
func UnregisterCleanupTask(name string) {
	GetGlobalCleanupManager().RemoveTask(name)
}

// RunGlobalCleanup immediately runs all global cleanup tasks
func RunGlobalCleanup() {
	GetGlobalCleanupManager().RunNow()
} 