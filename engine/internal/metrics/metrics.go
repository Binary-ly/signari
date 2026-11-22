// Package metrics exposes operational counters in the Prometheus text format.
//
// # Why this is written here rather than imported
//
// `prometheus/client_golang` is the obvious choice and it was not taken. It
// brings `prometheus/common`, `client_model`, `cespare/xxhash`, `beorn7/perks`,
// `munnerz/goautoneg` and the protobuf runtime -- around eight modules -- into a
// dependency graph that `docs/dependencies.md` keeps at thirteen direct entries
// on purpose, and it puts a protobuf decoder in an identity provider for an
// endpoint that in practice only ever emits text.
//
// The exposition format is a few lines of text per series. This package is the
// same decision that already produced a hand-written RADIUS server, LDAP server
// and SD-JWT implementation here: when the thing itself is smaller than the
// dependency, write it.
//
// What is given up is real and worth naming: no protobuf negotiation, no
// exemplars, no native histograms, and no free instrumentation of the Go runtime
// beyond what is collected below. All of that can be added if it is ever wanted,
// and none of it is needed to answer "is this deployment healthy".
//
// # THE LABEL RULE, which is why this file has a guard rather than a convention
//
// NO LABEL VALUE MAY EVER BE AN IDENTIFIER. Not a user id, subject, email,
// username, client id, session id, token, IP address or organisation id.
//
// Two separate things break if one gets through, and the first is the one that
// cannot be fixed afterwards:
//
//  1. ERASURE STOPS WORKING. Metrics are scraped into a time-series database
//     that lives outside this system, is retained for months, and is replicated
//     into dashboards and long-term storage. `subjects/{id}/erase` destroys the
//     subject's key here and reaches none of that. An identifier that reaches a
//     label has escaped the boundary the whole crypto-shredding design exists to
//     draw, permanently, and no amount of later care pulls it back.
//
//  2. CARDINALITY. One series per user is how a Prometheus server runs out of
//     memory, and it takes the monitoring down at the moment it is most needed.
//
// The guard is STRUCTURAL rather than a rule people are asked to follow. Every
// labelled metric declares the complete set of values each label may take, at
// construction. A value outside that set is recorded as "other" rather than
// emitted. So a bug that passes a user id where a status class was meant
// produces `{outcome="other"}` -- a lost data point, which is recoverable, and
// never a personal identifier in somebody's metrics store, which is not.
//
// `TestNoMetricLabelCanCarryAnIdentifier` holds the same property from the
// outside.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// OtherValue replaces any label value that was not declared.
//
// Deliberately not the empty string: an empty label reads as "this dimension was
// not applicable", which is a different fact from "something passed a value
// nobody expected" and would hide the bug this exists to contain.
const OtherValue = "other"

// Registry holds every metric a process exposes.
type Registry struct {
	mu      sync.RWMutex
	metrics []metric
}

type metric interface {
	write(w io.Writer)
	name() string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) register(m metric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.metrics {
		if existing.name() == m.name() {
			// A duplicate registration produces two HELP lines for one name,
			// which Prometheus rejects for the whole scrape -- so one careless
			// registration would take out every metric, not just its own.
			panic("metrics: " + m.name() + " is registered twice")
		}
	}
	r.metrics = append(r.metrics, m)
}

// Render writes the whole registry in the Prometheus text exposition format.
//
// Named Render rather than WriteTo: the latter is `io.WriterTo`, whose signature
// returns a byte count and an error, and a method that looks like an interface
// it does not satisfy is one somebody eventually passes to something expecting
// the real thing. `go vet` catches exactly this and did.
//
// Series are sorted so a diff between two scrapes is readable by a person, which
// the format does not require and anybody debugging one wants.
func (r *Registry) Render(w io.Writer) {
	r.mu.RLock()
	ms := make([]metric, len(r.metrics))
	copy(ms, r.metrics)
	r.mu.RUnlock()

	sort.Slice(ms, func(i, j int) bool { return ms[i].name() < ms[j].name() })
	for _, m := range ms {
		m.write(w)
	}
}

// ValueSet is the closed set of values one label may take.
//
// An interface rather than a map because the two kinds of closed set are closed
// at different times, and conflating them cost a panic in the first version of
// this package:
//
//   - A FixedSet is known when the metric is declared: status classes, grant
//     types, outcomes.
//   - A GrowableSet is filled during startup and closed before the first
//     request. Route patterns are the case: they are just as bounded — there are
//     as many as there are routes — but they are declared by 123 separate
//     registrations that all run after the metric exists.
//
// Treating the second as the first is what broke: the emptiness check ran at
// construction, before a single route had registered, and refused a label whose
// values were merely not there yet.
type ValueSet interface {
	// Has reports whether v may be exported as a label value.
	Has(v string) bool
	// Empty reports whether this set can never admit anything. Only a set that
	// is closed AND empty is a mistake; a growable one that is empty now is not.
	Empty() bool
}

// FixedSet is a value set known at declaration.
type FixedSet map[string]bool

func (s FixedSet) Has(v string) bool { return s[v] }
func (s FixedSet) Empty() bool       { return len(s) == 0 }

// GrowableSet is filled during startup and read concurrently afterwards.
//
// The mutex is not optional: registrations run while the process starts and
// lookups run on every request, and `go test` runs packages in parallel with
// servers built per test — so an unguarded map here is a data race that appears
// under `-race` and, occasionally, as a crash in production.
type GrowableSet struct {
	mu     sync.RWMutex
	values map[string]bool
}

// NewGrowableSet returns an empty growable set.
func NewGrowableSet() *GrowableSet {
	return &GrowableSet{values: map[string]bool{}}
}

// Add declares a value as safe to export.
func (s *GrowableSet) Add(v string) {
	s.mu.Lock()
	s.values[v] = true
	s.mu.Unlock()
}

func (s *GrowableSet) Has(v string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.values[v]
}

// Empty is always false: a growable set that holds nothing yet is not a
// declaration mistake, it is a declaration that has not finished.
func (s *GrowableSet) Empty() bool { return false }

// labelSet is a metric's label names and the closed set of values each may
// take, shared by every metric kind that has labels.
type labelSet struct {
	// names is fixed at construction and ordered; a series is keyed by the
	// joined values in this order.
	names []string
	// allowed is the closed set of values per label position. This is the guard:
	// anything else becomes OtherValue, so an identifier cannot reach a series
	// name even by mistake.
	allowed []ValueSet
}

// newLabelSet refuses a label with no declared values: an unbounded label is
// precisely what this package exists to prevent, and the shape that would
// introduce one is a caller who did not think about it.
func newLabelSet(name string, names []string, allowed []ValueSet) labelSet {
	if len(names) != len(allowed) {
		panic("metrics: " + name + " declares " + strconv.Itoa(len(names)) +
			" labels and " + strconv.Itoa(len(allowed)) + " value sets")
	}
	for i, set := range allowed {
		if set == nil || set.Empty() {
			panic("metrics: " + name + " label " + names[i] +
				" has no declared values; an unbounded label is how an " +
				"identifier reaches a metrics store")
		}
	}
	return labelSet{names: names, allowed: allowed}
}

// Counter is a value that only goes up.
type Counter struct {
	metricName string
	help       string
	labels     labelSet
	// info renders it as a gauge: a build-information series is a fact that
	// is 1, not a count.
	info bool

	mu     sync.Mutex
	values map[string]float64
}

// NewCounter registers a counter.
//
// `allowed` must have one entry per label name, giving every value that label
// may take. Passing an empty set for a label is refused rather than treated as
// "anything goes".
func (r *Registry) NewCounter(name, help string, labelNames []string, allowed []ValueSet) *Counter {
	c := &Counter{
		metricName: name, help: help, labels: newLabelSet(name, labelNames, allowed),
		values: map[string]float64{},
	}
	r.register(c)
	return c
}

func (c *Counter) name() string { return c.metricName }

// Add increases the series identified by these label values.
//
// Values are checked against the declared set here rather than at render time,
// so an undeclared value is contained at the moment it appears rather than
// accumulating its own series until somebody looks.
func (c *Counter) Add(delta float64, labelValues ...string) {
	key := c.labels.key(labelValues)
	c.mu.Lock()
	c.values[key] += delta
	c.mu.Unlock()
}

// Inc adds one.
func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// key normalises label values and joins them.
func (l labelSet) key(values []string) string {
	safe := make([]string, len(l.names))
	for i := range l.names {
		v := OtherValue
		if i < len(values) && l.allowed[i].Has(values[i]) {
			v = values[i]
		}
		safe[i] = v
	}
	// \x00 cannot appear in a declared value, so it cannot be forged into a
	// collision between two different label tuples.
	return strings.Join(safe, "\x00")
}

func (c *Counter) write(w io.Writer) {
	kind := "counter"
	if c.info {
		kind = "gauge"
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", c.metricName, c.help, c.metricName, kind)

	c.mu.Lock()
	keys := make([]string, 0, len(c.values))
	for k := range c.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	snapshot := make([]float64, len(keys))
	for i, k := range keys {
		snapshot[i] = c.values[k]
	}
	c.mu.Unlock()

	for i, k := range keys {
		fmt.Fprintf(w, "%s%s %g\n", c.metricName, c.labels.render(k, ""), snapshot[i])
	}
}

// render writes the labels a key stands for, followed by extra (a histogram's
// `le="…"`), or nothing when there are neither.
func (l labelSet) render(key, extra string) string {
	if len(l.names) == 0 && extra == "" {
		return ""
	}
	parts := strings.Split(key, "\x00")
	var b strings.Builder
	b.WriteByte('{')
	for i, name := range l.names {
		if i > 0 {
			b.WriteByte(',')
		}
		v := ""
		if i < len(parts) {
			v = parts[i]
		}
		b.WriteString(name)
		b.WriteString(`="`)
		b.WriteString(v)
		b.WriteByte('"')
	}
	if extra != "" {
		if len(l.names) > 0 {
			b.WriteByte(',')
		}
		b.WriteString(extra)
	}
	b.WriteByte('}')
	return b.String()
}

// Gauge is a value read at scrape time.
//
// A function rather than a stored number, because everything this process wants
// to report as a gauge -- pool connections, key counts -- is owned by something
// else that already knows the answer. Copying it into the registry on a timer
// would introduce a second source of truth that is wrong between ticks.
type Gauge struct {
	metricName string
	help       string
	read       func() float64
}

// NewGauge registers a gauge read from fn at scrape time.
func (r *Registry) NewGauge(name, help string, fn func() float64) *Gauge {
	g := &Gauge{metricName: name, help: help, read: fn}
	r.register(g)
	return g
}

func (g *Gauge) name() string { return g.metricName }

func (g *Gauge) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n",
		g.metricName, g.help, g.metricName, g.metricName, g.read())
}

// Histogram observes a distribution into fixed buckets.
//
// Bucket boundaries are given at construction because the right ones depend on
// what is being measured, and a default set is how a latency histogram ends up
// with every observation in the +Inf bucket.
type Histogram struct {
	metricName string
	help       string
	bounds     []float64
	labels     labelSet

	mu     sync.Mutex
	series map[string]*histogramSeries
}

type histogramSeries struct {
	counts []uint64
	sum    float64
	total  uint64
}

// NewHistogram registers a histogram. Bounds must be ascending.
func (r *Registry) NewHistogram(name, help string, bounds []float64) *Histogram {
	return r.NewHistogramVec(name, help, bounds, nil, nil)
}

// NewHistogramVec registers a histogram with labels, each from a closed set as
// a counter's are (3.08): the latency of one route is what a slow route looks
// like, and one histogram over every route hides it.
func (r *Registry) NewHistogramVec(name, help string, bounds []float64, labelNames []string,
	allowed []ValueSet) *Histogram {
	for i := 1; i < len(bounds); i++ {
		if bounds[i] <= bounds[i-1] {
			panic("metrics: " + name + " has non-ascending bucket bounds")
		}
	}
	h := &Histogram{
		metricName: name, help: help, bounds: bounds,
		labels: newLabelSet(name, labelNames, allowed),
		series: map[string]*histogramSeries{},
	}
	r.register(h)
	return h
}

func (h *Histogram) name() string { return h.metricName }

// Observe records one value in the series these label values name.
func (h *Histogram) Observe(v float64, labelValues ...string) {
	key := h.labels.key(labelValues)
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.series[key]
	if s == nil {
		s = &histogramSeries{counts: make([]uint64, len(h.bounds))}
		h.series[key] = s
	}
	s.sum += v
	s.total++
	for i, b := range h.bounds {
		if v <= b {
			s.counts[i]++
		}
	}
}

func (h *Histogram) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", h.metricName, h.help, h.metricName)

	h.mu.Lock()
	keys := make([]string, 0, len(h.series))
	for k := range h.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	snapshot := make([]histogramSeries, len(keys))
	for i, k := range keys {
		s := h.series[k]
		snapshot[i] = histogramSeries{counts: append([]uint64(nil), s.counts...), sum: s.sum, total: s.total}
	}
	h.mu.Unlock()
	if len(keys) == 0 && len(h.labels.names) == 0 {
		// An unlabelled histogram with nothing observed still shows its
		// buckets, at zero, as it always has.
		keys, snapshot = []string{""}, []histogramSeries{{counts: make([]uint64, len(h.bounds))}}
	}

	for i, k := range keys {
		s := snapshot[i]
		for j, b := range h.bounds {
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.metricName,
				h.labels.render(k, fmt.Sprintf(`le="%g"`, b)), s.counts[j])
		}
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.metricName, h.labels.render(k, `le="+Inf"`), s.total)
		fmt.Fprintf(w, "%s_sum%s %g\n", h.metricName, h.labels.render(k, ""), s.sum)
		fmt.Fprintf(w, "%s_count%s %d\n", h.metricName, h.labels.render(k, ""), s.total)
	}
}

// CounterFunc is a counter read at scrape time from something that already
// counts, such as the runtime's garbage collections.
type CounterFunc struct {
	metricName string
	help       string
	read       func() float64
}

// NewCounterFunc registers a counter read from fn, which must never go down.
func (r *Registry) NewCounterFunc(name, help string, fn func() float64) *CounterFunc {
	c := &CounterFunc{metricName: name, help: help, read: fn}
	r.register(c)
	return c
}

func (c *CounterFunc) name() string { return c.metricName }

func (c *CounterFunc) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %g\n",
		c.metricName, c.help, c.metricName, c.metricName, c.read())
}

// NewInfo registers a gauge that is always 1, carrying this process's own
// facts as labels: the release and toolchain it was built from. Each label has
// exactly the one value given, so it is a closed set of one.
func (r *Registry) NewInfo(name, help string, labelNames, values []string) *Counter {
	allowed := make([]ValueSet, len(values))
	for i, v := range values {
		allowed[i] = FixedSet{v: true}
	}
	c := r.NewCounter(name, help, labelNames, allowed)
	c.info = true
	c.Inc(values...)
	return c
}
