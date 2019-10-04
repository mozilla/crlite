package telemetry

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/armon/go-metrics"
	"github.com/golang/glog"
)

// InmemSignal is used to listen for a given signal, and when received,
// to dump the current metrics from the InmemSink to an io.Writer
type MetricsDumper struct {
	inm    *metrics.InmemSink
	w      io.Writer
	stopCh chan struct{}
	ticker *time.Ticker
}

func NewMetricsDumper(sink *metrics.InmemSink, period time.Duration) *MetricsDumper {
	obj := &MetricsDumper{
		inm:    sink,
		w:      os.Stderr,
		stopCh: make(chan struct{}),
		ticker: time.NewTicker(period),
	}

	go obj.run()

	return obj
}

func (i *MetricsDumper) run() {
	for {
		select {
		case <-i.ticker.C:
			i.dumpStats()
		case <-i.stopCh:
			return
		}
	}
}

func (i *MetricsDumper) Stop() {
	close(i.stopCh)
	i.ticker.Stop()
}

// dumpStats is used to dump the data to output writer
func (i *MetricsDumper) dumpStats() {
	buf := bytes.NewBuffer(nil)

	data := i.inm.Data()
	// Skip the last period which is still being aggregated
	for j := 0; j < len(data)-1; j++ {
		intv := data[j]
		intv.RLock()
		for _, val := range intv.Gauges {
			name := i.flattenLabels(val.Name, val.Labels)
			fmt.Fprintf(buf, "[%v][G] '%s': %0.3f\n", intv.Interval, name, val.Value)
		}
		for name, vals := range intv.Points {
			for _, val := range vals {
				fmt.Fprintf(buf, "[%v][P] '%s': %0.3f\n", intv.Interval, name, val)
			}
		}
		for _, agg := range intv.Counters {
			name := i.flattenLabels(agg.Name, agg.Labels)
			fmt.Fprintf(buf, "[%v][C] '%s': %s\n", intv.Interval, name, agg.AggregateSample)
		}
		for _, agg := range intv.Samples {
			name := i.flattenLabels(agg.Name, agg.Labels)
			fmt.Fprintf(buf, "[%v][S] '%s': %s\n", intv.Interval, name, agg.AggregateSample)
		}
		intv.RUnlock()
	}

	// Write out the bytes
	_, err := i.w.Write(buf.Bytes())
	if err != nil {
		glog.Warningf("Could not emit stats: %v", err)
	}
}

// Flattens the key for formatting along with its labels, removes spaces
func (i *MetricsDumper) flattenLabels(name string, labels []metrics.Label) string {
	buf := bytes.NewBufferString(name)
	replacer := strings.NewReplacer(" ", "_", ":", "_")

	for _, label := range labels {
		_, _ = replacer.WriteString(buf, ".")
		_, _ = replacer.WriteString(buf, label.Value)
	}

	return buf.String()
}
