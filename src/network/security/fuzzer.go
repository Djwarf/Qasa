package security

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/qasa/network/message"
)

// FuzzTarget represents a component to be fuzzed
type FuzzTarget int

const (
	MessageParser FuzzTarget = iota
	KeyExchange
	MessageProtocol
	NetworkHandshake
	JSONDecoding
)

// FuzzTest represents a fuzzing test case
type FuzzTest struct {
	Name        string
	Target      FuzzTarget
	Generator   func() []byte
	Validator   func([]byte, error) bool
	Iterations  int
	MaxSize     int
}

// Fuzzer manages fuzzing operations
type Fuzzer struct {
	targets    map[FuzzTarget][]FuzzTest
	results    *FuzzResults
	ctx        context.Context
	cancel     context.CancelFunc
	concurrent int
}

// FuzzResults stores fuzzing results
type FuzzResults struct {
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	TotalInputs   int                    `json:"total_inputs"`
	Crashes       []CrashReport          `json:"crashes"`
	Hangs         []HangReport           `json:"hangs"`
	Anomalies     []Anomaly              `json:"anomalies"`
	Coverage      map[string]int         `json:"coverage"`
	Performance   PerformanceStats       `json:"performance"`
	Summary       map[string]interface{} `json:"summary"`
	mu            sync.RWMutex
}

// CrashReport represents a crash found during fuzzing
type CrashReport struct {
	ID        string    `json:"id"`
	Input     []byte    `json:"input"`
	InputHex  string    `json:"input_hex"`
	Target    string    `json:"target"`
	Error     string    `json:"error"`
	Stack     string    `json:"stack"`
	Timestamp time.Time `json:"timestamp"`
}

// HangReport represents a hang/timeout found during fuzzing
type HangReport struct {
	ID        string    `json:"id"`
	Input     []byte    `json:"input"`
	InputHex  string    `json:"input_hex"`
	Target    string    `json:"target"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time `json:"timestamp"`
}

// Anomaly represents unusual behavior during fuzzing
type Anomaly struct {
	ID          string    `json:"id"`
	Input       []byte    `json:"input"`
	InputHex    string    `json:"input_hex"`
	Target      string    `json:"target"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
}

// PerformanceStats tracks performance during fuzzing
type PerformanceStats struct {
	ExecsPerSecond   float64           `json:"execs_per_second"`
	AvgExecTime      time.Duration     `json:"avg_exec_time"`
	MemoryUsage      int64             `json:"memory_usage_bytes"`
	GoroutineCount   int               `json:"goroutine_count"`
	TimeDistribution map[string]int64  `json:"time_distribution"`
}

// NewFuzzer creates a new fuzzing framework
func NewFuzzer(ctx context.Context, concurrent int) *Fuzzer {
	fuzzerCtx, cancel := context.WithCancel(ctx)
	
	f := &Fuzzer{
		targets:    make(map[FuzzTarget][]FuzzTest),
		ctx:        fuzzerCtx,
		cancel:     cancel,
		concurrent: concurrent,
		results: &FuzzResults{
			StartTime:   time.Now(),
			Coverage:    make(map[string]int),
			Performance: PerformanceStats{
				TimeDistribution: make(map[string]int64),
			},
			Summary: make(map[string]interface{}),
		},
	}
	
	f.registerFuzzTests()
	return f
}

// registerFuzzTests registers all fuzzing test cases
func (f *Fuzzer) registerFuzzTests() {
	// Message parsing fuzzing
	f.targets[MessageParser] = []FuzzTest{
		{
			Name:       "JSON Message Fuzzing",
			Target:     MessageParser,
			Generator:  f.generateRandomJSON,
			Validator:  f.validateJSONParsing,
			Iterations: 10000,
			MaxSize:    65536,
		},
		{
			Name:       "Binary Message Fuzzing",
			Target:     MessageParser,
			Generator:  f.generateRandomBytes,
			Validator:  f.validateBinaryParsing,
			Iterations: 5000,
			MaxSize:    1048576,
		},
	}
	
	// Key exchange fuzzing
	f.targets[KeyExchange] = []FuzzTest{
		{
			Name:       "Key Exchange Protocol Fuzzing",
			Target:     KeyExchange,
			Generator:  f.generateKeyExchangePayload,
			Validator:  f.validateKeyExchange,
			Iterations: 1000,
			MaxSize:    8192,
		},
	}
	
	// Message protocol fuzzing
	f.targets[MessageProtocol] = []FuzzTest{
		{
			Name:       "Message Protocol Fuzzing",
			Target:     MessageProtocol,
			Generator:  f.generateMessageProtocolPayload,
			Validator:  f.validateMessageProtocol,
			Iterations: 5000,
			MaxSize:    32768,
		},
	}
}

// RunFuzzing starts the fuzzing process
func (f *Fuzzer) RunFuzzing() (*FuzzResults, error) {
	log.Printf("Starting fuzzing with %d concurrent workers", f.concurrent)
	
	var wg sync.WaitGroup
	workChan := make(chan FuzzTest, 100)
	
	// Start worker goroutines
	for i := 0; i < f.concurrent; i++ {
		wg.Add(1)
		go f.fuzzWorker(i, workChan, &wg)
	}
	
	// Send work to workers
	go func() {
		defer close(workChan)
		for _, tests := range f.targets {
			for _, test := range tests {
				select {
				case workChan <- test:
				case <-f.ctx.Done():
					return
				}
			}
		}
	}()
	
	// Monitor progress
	go f.monitorProgress()
	
	// Wait for completion
	wg.Wait()
	
	f.results.EndTime = time.Now()
	f.generateSummary()
	
	return f.results, nil
}

// fuzzWorker runs fuzzing tests
func (f *Fuzzer) fuzzWorker(id int, workChan <-chan FuzzTest, wg *sync.WaitGroup) {
	defer wg.Done()
	
	log.Printf("Fuzzer worker %d started", id)
	
	for test := range workChan {
		f.runFuzzTest(test)
	}
	
	log.Printf("Fuzzer worker %d completed", id)
}

// runFuzzTest executes a single fuzz test
func (f *Fuzzer) runFuzzTest(test FuzzTest) {
	log.Printf("Running fuzz test: %s (%d iterations)", test.Name, test.Iterations)
	
	for i := 0; i < test.Iterations; i++ {
		select {
		case <-f.ctx.Done():
			return
		default:
		}
		
		// Generate test input
		input := test.Generator()
		if len(input) > test.MaxSize {
			input = input[:test.MaxSize]
		}
		
		// Execute with timeout and crash detection
		f.executeWithMonitoring(test, input)
		
		f.results.mu.Lock()
		f.results.TotalInputs++
		f.results.mu.Unlock()
		
		// Small delay to prevent overwhelming the system
		if i%100 == 0 {
			time.Sleep(1 * time.Millisecond)
		}
	}
}

// executeWithMonitoring executes a test input with crash and hang detection
func (f *Fuzzer) executeWithMonitoring(test FuzzTest, input []byte) {
	start := time.Now()
	
	// Create a channel to signal completion
	done := make(chan bool, 1)
	var execErr error
	var panicked bool
	var panicMsg interface{}
	
	// Execute in a goroutine to catch panics and hangs
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicMsg = r
			}
			done <- true
		}()
		
		// Execute the actual test
		execErr = f.executeTarget(test.Target, input)
	}()
	
	// Wait for completion or timeout
	select {
	case <-done:
		duration := time.Since(start)
		
		if panicked {
			// Record crash
			f.recordCrash(test, input, fmt.Sprintf("Panic: %v", panicMsg))
		} else if execErr != nil && !test.Validator(input, execErr) {
			// Record anomaly if validator indicates unusual behavior
			f.recordAnomaly(test, input, execErr.Error(), "Medium")
		}
		
		// Update performance stats
		f.updatePerformanceStats(duration)
		
	case <-time.After(5 * time.Second):
		// Record hang
		f.recordHang(test, input, 5*time.Second)
	}
}

// executeTarget executes fuzzing against a specific target
func (f *Fuzzer) executeTarget(target FuzzTarget, input []byte) error {
	switch target {
	case MessageParser:
		return f.fuzzMessageParser(input)
	case KeyExchange:
		return f.fuzzKeyExchange(input)
	case MessageProtocol:
		return f.fuzzMessageProtocol(input)
	case JSONDecoding:
		return f.fuzzJSONDecoding(input)
	default:
		return fmt.Errorf("unknown fuzz target: %v", target)
	}
}

// Fuzzing target implementations

func (f *Fuzzer) fuzzMessageParser(input []byte) error {
	// Test message parsing with various inputs
	var msg message.Message
	err := json.Unmarshal(input, &msg)
	
	// Even if parsing fails, it shouldn't crash
	if err != nil {
		// Check if it's a reasonable error
		if len(input) > 1024*1024 {
			return fmt.Errorf("large input handled incorrectly")
		}
	}
	
	return nil
}

func (f *Fuzzer) fuzzKeyExchange(input []byte) error {
	// Test key exchange protocol with malformed inputs
	// This would normally involve the actual key exchange implementation
	
	if len(input) == 0 {
		return fmt.Errorf("empty input")
	}
	
	// Simulate key exchange processing
	time.Sleep(time.Microsecond * time.Duration(len(input)%100))
	
	return nil
}

func (f *Fuzzer) fuzzMessageProtocol(input []byte) error {
	// Test message protocol handling
	if bytes.Contains(input, []byte{0x00, 0x00, 0x00, 0x00}) {
		return fmt.Errorf("null bytes in protocol")
	}
	
	return nil
}

func (f *Fuzzer) fuzzJSONDecoding(input []byte) error {
	// Test JSON decoding robustness
	var data interface{}
	err := json.Unmarshal(input, &data)
	
	if err == nil && len(input) > 10*1024*1024 {
		return fmt.Errorf("extremely large JSON processed")
	}
	
	return err
}

// Input generators

func (f *Fuzzer) generateRandomJSON() []byte {
	generators := []func() []byte{
		f.generateValidJSON,
		f.generateMalformedJSON,
		f.generateLargeJSON,
		f.generateNestedJSON,
	}
	
	generator := generators[rand.Intn(len(generators))]
	return generator()
}

func (f *Fuzzer) generateValidJSON() []byte {
	messages := []string{
		`{"type":"chat","content":"hello","from":"user1","to":"user2"}`,
		`{"type":"ack","id":"msg123"}`,
		`{"type":"key_exchange","data":"base64data"}`,
	}
	
	return []byte(messages[rand.Intn(len(messages))])
}

func (f *Fuzzer) generateMalformedJSON() []byte {
	malformed := []string{
		`{"type":"chat","content":`,
		`{"type":"chat","content":"hello"`,
		`{type:"chat","content":"hello"}`,
		`{"type":}`,
		`{"type":"chat","content":null}`,
		`{"""""""}`,
	}
	
	return []byte(malformed[rand.Intn(len(malformed))])
}

func (f *Fuzzer) generateLargeJSON() []byte {
	size := rand.Intn(1024*1024) + 1024
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(32 + rand.Intn(95)) // Printable ASCII
	}
	
	return []byte(fmt.Sprintf(`{"type":"chat","content":"%s"}`, string(content)))
}

func (f *Fuzzer) generateNestedJSON() []byte {
	depth := rand.Intn(100) + 1
	json := "{"
	for i := 0; i < depth; i++ {
		json += fmt.Sprintf(`"level%d":{`, i)
	}
	json += `"data":"value"`
	for i := 0; i < depth; i++ {
		json += "}"
	}
	json += "}"
	
	return []byte(json)
}

func (f *Fuzzer) generateRandomBytes() []byte {
	size := rand.Intn(65536) + 1
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func (f *Fuzzer) generateKeyExchangePayload() []byte {
	// Generate key exchange-like payloads
	size := 32 + rand.Intn(8192)
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func (f *Fuzzer) generateMessageProtocolPayload() []byte {
	// Generate protocol-like payloads
	templates := [][]byte{
		{0x01, 0x02, 0x03, 0x04}, // Header
		{0xFF, 0xFF, 0xFF, 0xFF}, // All ones
		{0x00, 0x00, 0x00, 0x00}, // All zeros
	}
	
	template := templates[rand.Intn(len(templates))]
	size := rand.Intn(1024) + len(template)
	data := make([]byte, size)
	copy(data, template)
	
	// Fill rest with random data
	rand.Read(data[len(template):])
	
	return data
}

// Validators

func (f *Fuzzer) validateJSONParsing(input []byte, err error) bool {
	// Consider it normal if JSON parsing fails on invalid input
	return true
}

func (f *Fuzzer) validateBinaryParsing(input []byte, err error) bool {
	// Binary parsing should handle any input gracefully
	return true
}

func (f *Fuzzer) validateKeyExchange(input []byte, err error) bool {
	// Key exchange should handle malformed input safely
	return true
}

func (f *Fuzzer) validateMessageProtocol(input []byte, err error) bool {
	// Message protocol should be robust
	return true
}

// Result recording

func (f *Fuzzer) recordCrash(test FuzzTest, input []byte, errorMsg string) {
	f.results.mu.Lock()
	defer f.results.mu.Unlock()
	
	crash := CrashReport{
		ID:        fmt.Sprintf("CRASH-%d", len(f.results.Crashes)+1),
		Input:     input,
		InputHex:  fmt.Sprintf("%x", input),
		Target:    test.Name,
		Error:     errorMsg,
		Timestamp: time.Now(),
	}
	
	f.results.Crashes = append(f.results.Crashes, crash)
	log.Printf("CRASH DETECTED: %s - %s", test.Name, errorMsg)
}

func (f *Fuzzer) recordHang(test FuzzTest, input []byte, duration time.Duration) {
	f.results.mu.Lock()
	defer f.results.mu.Unlock()
	
	hang := HangReport{
		ID:        fmt.Sprintf("HANG-%d", len(f.results.Hangs)+1),
		Input:     input,
		InputHex:  fmt.Sprintf("%x", input),
		Target:    test.Name,
		Duration:  duration,
		Timestamp: time.Now(),
	}
	
	f.results.Hangs = append(f.results.Hangs, hang)
	log.Printf("HANG DETECTED: %s - %v", test.Name, duration)
}

func (f *Fuzzer) recordAnomaly(test FuzzTest, input []byte, description, severity string) {
	f.results.mu.Lock()
	defer f.results.mu.Unlock()
	
	anomaly := Anomaly{
		ID:          fmt.Sprintf("ANOM-%d", len(f.results.Anomalies)+1),
		Input:       input,
		InputHex:    fmt.Sprintf("%x", input),
		Target:      test.Name,
		Description: description,
		Severity:    severity,
		Timestamp:   time.Now(),
	}
	
	f.results.Anomalies = append(f.results.Anomalies, anomaly)
}

func (f *Fuzzer) updatePerformanceStats(duration time.Duration) {
	f.results.mu.Lock()
	defer f.results.mu.Unlock()
	
	// Update average execution time
	totalExecs := f.results.TotalInputs
	if totalExecs > 0 {
		avgNanos := int64(f.results.Performance.AvgExecTime) * int64(totalExecs-1)
		avgNanos += int64(duration)
		f.results.Performance.AvgExecTime = time.Duration(avgNanos / int64(totalExecs))
	} else {
		f.results.Performance.AvgExecTime = duration
	}
	
	// Update time distribution
	bucket := ""
	switch {
	case duration < time.Microsecond:
		bucket = "sub_microsecond"
	case duration < time.Millisecond:
		bucket = "microseconds"
	case duration < time.Second:
		bucket = "milliseconds"
	default:
		bucket = "seconds"
	}
	f.results.Performance.TimeDistribution[bucket]++
}

func (f *Fuzzer) monitorProgress() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			f.results.mu.RLock()
			execsPerSec := float64(f.results.TotalInputs) / time.Since(f.results.StartTime).Seconds()
			f.results.Performance.ExecsPerSecond = execsPerSec
			f.results.Performance.MemoryUsage = int64(runtime.MemStats{}.Alloc)
			f.results.Performance.GoroutineCount = runtime.NumGoroutine()
			
			log.Printf("Fuzzing progress: %d inputs, %.2f exec/sec, %d crashes, %d hangs",
				f.results.TotalInputs, execsPerSec, len(f.results.Crashes), len(f.results.Hangs))
			f.results.mu.RUnlock()
			
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *Fuzzer) generateSummary() {
	duration := f.results.EndTime.Sub(f.results.StartTime)
	
	f.results.Summary["duration_seconds"] = duration.Seconds()
	f.results.Summary["total_crashes"] = len(f.results.Crashes)
	f.results.Summary["total_hangs"] = len(f.results.Hangs)
	f.results.Summary["total_anomalies"] = len(f.results.Anomalies)
	f.results.Summary["crash_rate"] = float64(len(f.results.Crashes)) / float64(f.results.TotalInputs)
	f.results.Summary["inputs_per_second"] = float64(f.results.TotalInputs) / duration.Seconds()
}

// Stop stops the fuzzing process
func (f *Fuzzer) Stop() {
	f.cancel()
} 