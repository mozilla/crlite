package utils

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type OperationStatus struct {
	// Identifier of this Status Update
	Identifier string
	// Start contains the requested starting index of the operation.
	Start uint64
	// Current contains the greatest index that has been processed.
	Current uint64
	// Length contains the total number of entries.
	Length uint64
}

func (status OperationStatus) Percentage() float32 {
	total := float32(status.Length - status.Start)
	done := float32(status.Current - status.Start)

	if total == 0 {
		return 100
	}
	return done * 100 / total
}

type OperationData struct {
	lastTime       time.Time
	lastCount      uint64
	length         uint64
	ticksPerMinute float64
}

func NewOperationData() *OperationData {
	return &OperationData{
		lastTime:       time.Time{},
		lastCount:      uint64(0),
		length:         uint64(0),
		ticksPerMinute: float64(0.0),
	}
}

type ProgressMonitor struct {
	operations   map[string]OperationData
	cachedString string
}

func NewProgressMonitor() *ProgressMonitor {
	return &ProgressMonitor{
		operations:   make(map[string]OperationData),
		cachedString: "?",
	}
}

func (pm *ProgressMonitor) getTimeRemaining() time.Duration {
	remaining := pm.CurrentLength() - pm.CurrentPosition()
	rate := pm.getInstantRateMinute()
	minutesRemaining := float64(remaining) / rate
	return time.Duration(minutesRemaining) * time.Minute
}

func (pm *ProgressMonitor) CurrentPercentage() float64 {
	return float64(pm.CurrentPosition()) / float64(pm.CurrentLength()) * 100.0
}

func (pm *ProgressMonitor) CurrentPosition() uint64 {
	var completed uint64
	for _, op := range pm.operations {
		completed += op.lastCount
	}
	return completed
}

func (pm *ProgressMonitor) CurrentLength() uint64 {
	var total uint64
	for _, op := range pm.operations {
		total += op.length
	}
	return total
}

func (pm *ProgressMonitor) String() string {
	return pm.cachedString
}

func (pm *ProgressMonitor) UpdateCount(identifier string, newCount uint64) error {
	opObj, ok := pm.operations[identifier]
	if !ok {
		opObj = *NewOperationData()
	}

	nowTime := time.Now()
	countChange := newCount - opObj.lastCount

	if !opObj.lastTime.IsZero() {
		timeElapsed := nowTime.Sub(opObj.lastTime)
		opObj.ticksPerMinute = float64(countChange) / timeElapsed.Minutes()
	}
	pm.cachedString = fmt.Sprintf("%.1f%% (%d of %d) Rate: %.0f/minute (%s remaining)",
		pm.CurrentPercentage(), pm.CurrentPosition(), pm.CurrentLength(),
		pm.getInstantRateMinute(), pm.getTimeRemaining())

	opObj.lastCount = newCount
	opObj.lastTime = nowTime
	pm.operations[identifier] = opObj

	return nil
}

func (pm *ProgressMonitor) UpdateLength(identifier string, newLength uint64) error {
	opObj, ok := pm.operations[identifier]
	if !ok {
		opObj = *NewOperationData()
	}
	opObj.length = newLength
	pm.operations[identifier] = opObj
	return nil
}

func (pm *ProgressMonitor) getInstantRateMinute() float64 {
	var rate float64
	for _, op := range pm.operations {
		rate += op.ticksPerMinute
	}
	return rate
}

func clearLine() {
	fmt.Printf("\x1b[80D\x1b[2K")
}

type ProgressDisplay struct {
	statusChan chan OperationStatus
}

func NewProgressDisplay() *ProgressDisplay {
	return &ProgressDisplay{
		statusChan: make(chan OperationStatus, 1),
	}
}

func (pd *ProgressDisplay) UpdateProgress(identifier string, start uint64, index uint64, upTo uint64) {
	pd.statusChan <- OperationStatus{identifier, start, index, upTo}
}

func (pd *ProgressDisplay) Close() {
	close(pd.statusChan)
}

func (pd *ProgressDisplay) StartDisplay(wg *sync.WaitGroup) {
	wg.Add(1)

	go func() {
		defer wg.Done()
		symbols := []string{"|", "/", "-", "\\"}
		symbolIndex := 0

		status, ok := <-pd.statusChan
		if !ok {
			return
		}

		isInteractive := strings.Contains(os.Getenv("TERM"), "xterm") || strings.Contains(os.Getenv("TERM"), "screen")

		var tickSpeed time.Duration
		if isInteractive {
			tickSpeed = 200 * time.Millisecond
		} else {
			tickSpeed = 1 * time.Minute
		}

		printTicker := time.NewTicker(tickSpeed)
		defer printTicker.Stop()

		// Speed statistics
		progressMonitor := NewProgressMonitor()

		for {
			select {
			case status, ok = <-pd.statusChan:
				if !ok {
					// Channel closed
					if isInteractive {
						clearLine()
					}
					return
				}

				// Track speed statistics
				progressMonitor.UpdateCount(status.Identifier, status.Current-status.Start)
				progressMonitor.UpdateLength(status.Identifier, status.Length-status.Start)
			case <-printTicker.C:
				if isInteractive {
					clearLine()
					symbolIndex = (symbolIndex + 1) % len(symbols)
					fmt.Printf("%s %s", symbols[symbolIndex], progressMonitor)
				} else {
					fmt.Printf("%s\n", progressMonitor)
				}
			}

		}
	}()
}
