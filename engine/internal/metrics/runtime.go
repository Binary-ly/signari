package metrics

import (
	"runtime"
	rtm "runtime/metrics"
	"time"
)

// processStart is when this process began, as near as the package can tell.
var processStart = time.Now()

// RegisterRuntime adds the Go runtime's own series (3.08): goroutines, heap
// and total memory, garbage collections, and when the process started. A leak
// of goroutines or memory showed only as the process being killed, and a
// restart only as a gap.
func (r *Registry) RegisterRuntime() {
	r.NewGauge("go_goroutines", "Goroutines that currently exist.",
		func() float64 { return float64(runtime.NumGoroutine()) })
	r.NewGauge("go_heap_objects_bytes", "Bytes of memory occupied by live and not yet freed heap objects.",
		func() float64 { return runtimeValue("/memory/classes/heap/objects:bytes") })
	r.NewGauge("go_memory_total_bytes", "All memory mapped by the Go runtime.",
		func() float64 { return runtimeValue("/memory/classes/total:bytes") })
	r.NewCounterFunc("go_gc_cycles_total", "Completed garbage collection cycles.",
		func() float64 { return runtimeValue("/gc/cycles/total:gc-cycles") })
	r.NewGauge("process_start_time_seconds", "When this process started, in seconds since the epoch.",
		func() float64 { return float64(processStart.UnixNano()) / 1e9 })
}

// runtimeValue reads one runtime/metrics sample as a number.
func runtimeValue(name string) float64 {
	s := []rtm.Sample{{Name: name}}
	rtm.Read(s)
	switch s[0].Value.Kind() {
	case rtm.KindUint64:
		return float64(s[0].Value.Uint64())
	case rtm.KindFloat64:
		return s[0].Value.Float64()
	}
	return 0
}
