package beacon

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Config configures the Beacon client. TenantSlug is intentionally not a field here —
// the server resolves which tenant a trace belongs to from the API key itself, so a
// single API key is all a service needs.
type Config struct {
	IngestURL   string
	APIKey      string
	ServiceName string
	Environment string
	BatchSize   int
	FlushPeriod time.Duration
	// SampleRate is the fraction of requests actually traced and sent to Beacon, from 0.0
	// (none) to 1.0 (all, the default). Lower it in high-traffic services to control ingest
	// volume and stay within your plan's monthly quota — e.g. 0.1 traces ~10% of requests.
	// Unsampled requests skip tracing entirely (no queueing, no network call), so this
	// reduces load on your service too, not just what you send. A value outside (0, 1]
	// (including the zero value, so an unset Config defaults to fully sampled) is treated
	// as 1.0.
	SampleRate float64
}

type User struct {
	ID            string `json:"id,omitempty"`
	Email         string `json:"email,omitempty"`
	Username      string `json:"username,omitempty"`
	IP            string `json:"ip,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

type StackFrame struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Function string   `json:"function"`
	Snippet  []string `json:"snippet,omitempty"`
}

type Exception struct {
	Type       string       `json:"type"`
	Message    string       `json:"message"`
	Handled    bool         `json:"handled"`
	Stacktrace []StackFrame `json:"stacktrace,omitempty"`
}

type Breadcrumb struct {
	Category  string                 `json:"category"` // "log", "http", "query", "navigation", "ui", "user", "error"
	Message   string                 `json:"message"`
	Level     string                 `json:"level,omitempty"` // "info", "warning", "error", "debug"
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// SpanMetadata carries well-known fields for infrastructure spans (database/cache calls).
// For anything else, use Span.Tags via CustomSpan.SetTag.
type SpanMetadata struct {
	Driver       string  `json:"driver,omitempty"`
	Table        string  `json:"table,omitempty"`
	RowsReturned int     `json:"rows_returned,omitempty"`
	Hit          *bool   `json:"hit,omitempty"`
	Key          string  `json:"key,omitempty"`
	Op           string  `json:"op,omitempty"`
	StatusCode   int     `json:"status_code,omitempty"`
	Queue        string  `json:"queue,omitempty"`
	Connection   string  `json:"connection,omitempty"`
	Attempts     int     `json:"attempts,omitempty"`
	WaitMs       float64 `json:"wait_ms,omitempty"`
}

type Span struct {
	SpanID       string            `json:"span_id,omitempty"`
	ParentSpanID string            `json:"parent_span_id,omitempty"`
	Type         string            `json:"type"` // database, cache, http, job, middleware, custom
	Name         string            `json:"name"`
	StartMs      float64           `json:"start_ms"`
	DurationMs   float64           `json:"duration_ms"`
	Metadata     *SpanMetadata     `json:"metadata,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

type RequestContext struct {
	Method     string            `json:"method"`
	Route      string            `json:"route"`
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	ClientIP   string            `json:"client_ip,omitempty"`
}

type TraceEvent struct {
	ID           string          `json:"id"`
	ProjectKey   string          `json:"project_key"`
	ServiceName  string          `json:"service_name"`
	Environment  string          `json:"environment"`
	Runtime      string          `json:"runtime"`
	TraceID      string          `json:"trace_id"`
	ParentSpan   string          `json:"parent_span,omitempty"`
	Timestamp    time.Time       `json:"timestamp"`
	DurationMs   float64         `json:"duration_ms"`
	User         *User           `json:"user,omitempty"`
	Request      *RequestContext `json:"request,omitempty"`
	Spans        []Span          `json:"spans"`
	Breadcrumbs  []Breadcrumb    `json:"breadcrumbs,omitempty"`
	Exception    *Exception      `json:"exception,omitempty"`
	HasException bool            `json:"has_exception"`
}

type Client struct {
	cfg        Config
	queue      chan *TraceEvent
	httpClient *http.Client
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

var (
	globalClient *Client
	globalMu     sync.RWMutex
)

// Init starts the Beacon client. Call once at startup; defer beacon.Close() to flush
// on shutdown.
func Init(cfg Config) *Client {
	if cfg.IngestURL == "" {
		cfg.IngestURL = "http://localhost:8443"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushPeriod <= 0 {
		cfg.FlushPeriod = 500 * time.Millisecond
	}
	if cfg.Environment == "" {
		cfg.Environment = "production"
	}
	if cfg.SampleRate <= 0 || cfg.SampleRate > 1 {
		cfg.SampleRate = 1.0
	}

	c := &Client{
		cfg:   cfg,
		queue: make(chan *TraceEvent, 2048),
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
		stopChan: make(chan struct{}),
	}

	c.wg.Add(1)
	go c.worker()

	globalMu.Lock()
	globalClient = c
	globalMu.Unlock()

	return c
}

func GetClient() *Client {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalClient
}

// ServiceName returns the service name this client was configured with.
func (c *Client) ServiceName() string {
	return c.cfg.ServiceName
}

func (c *Client) SendTrace(event *TraceEvent) {
	if event == nil {
		return
	}
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.TraceID == "" {
		event.TraceID = event.ID
	}
	if event.ProjectKey == "" {
		event.ProjectKey = c.cfg.APIKey
	}
	if event.ServiceName == "" {
		event.ServiceName = c.cfg.ServiceName
	}
	if event.Environment == "" {
		event.Environment = c.cfg.Environment
	}
	if event.Runtime == "" {
		event.Runtime = "go1.26"
	}

	select {
	case c.queue <- event:
	default:
		// Drop rather than block customer app
	}
}

func (c *Client) worker() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.cfg.FlushPeriod)
	defer ticker.Stop()

	batch := make([]*TraceEvent, 0, c.cfg.BatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		toSend := make([]*TraceEvent, len(batch))
		copy(toSend, batch)
		batch = batch[:0]

		go c.postBatch(toSend)
	}

	for {
		select {
		case item := <-c.queue:
			batch = append(batch, item)
			if len(batch) >= c.cfg.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-c.stopChan:
			// Flush remaining
			for {
				select {
				case item := <-c.queue:
					batch = append(batch, item)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (c *Client) postBatch(events []*TraceEvent) {
	data, err := json.Marshal(events)
	if err != nil {
		return
	}

	url := fmt.Sprintf("%s/v1/batch", c.cfg.IngestURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Beacon-Key", c.cfg.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[TrustPort Beacon] Failed to send telemetry: %v", err)
		return
	}
	defer resp.Body.Close()
}

func (c *Client) FlushAndClose() {
	close(c.stopChan)
	c.wg.Wait()
}

func Close() {
	if c := GetClient(); c != nil {
		c.FlushAndClose()
	}
}

type ctxKey string

const (
	userContextKey  ctxKey = "beacon_user"
	traceContextKey ctxKey = "beacon_trace_ctx"
)

// GenerateTraceID generates a standard 16-byte (32 lowercase hex) trace identifier.
func GenerateTraceID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return strings.ReplaceAll(uuid.New().String(), "-", "")
	}
	return hex.EncodeToString(b[:])
}

// GenerateSpanID generates an 8-byte (16 lowercase hex) span identifier.
func GenerateSpanID() string {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// ParseTraceparent extracts the trace ID and parent span ID from a W3C traceparent header.
// Format: {version}-{trace_id}-{parent_id}-{trace_flags}, e.g. "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".
func ParseTraceparent(header string) (traceID string, parentSpanID string, ok bool) {
	header = strings.TrimSpace(header)
	if len(header) != 55 {
		return "", "", false
	}
	parts := strings.Split(header, "-")
	if len(parts) != 4 {
		return "", "", false
	}
	if len(parts[0]) != 2 || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return "", "", false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", "", false
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return "", "", false
	}
	if parts[1] == "00000000000000000000000000000000" || parts[2] == "0000000000000000" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

type TraceContext struct {
	mu           sync.Mutex
	TraceID      string
	SpanID       string
	ParentSpanID string
	StartTime    time.Time
	User         *User
	Spans        []Span
	Breadcrumbs  []Breadcrumb
}

func (tc *TraceContext) AddSpan(s Span) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.Spans = append(tc.Spans, s)
}

// AddJobSpan records a background job or queue execution span with job metadata.
func (tc *TraceContext) AddJobSpan(jobName, queue string, durationMs, waitMs float64, tags map[string]string) {
	if tc == nil {
		return
	}
	if tags == nil {
		tags = make(map[string]string)
	}
	tags["job"] = jobName
	if queue != "" {
		tags["queue"] = queue
	}
	span := Span{
		SpanID:     GenerateSpanID(),
		Type:       "job",
		Name:       fmt.Sprintf("JOB %s", jobName),
		DurationMs: durationMs,
		Metadata: &SpanMetadata{
			Queue:  queue,
			WaitMs: waitMs,
		},
		Tags: tags,
	}
	tc.AddSpan(span)
}

func (tc *TraceContext) AddBreadcrumb(b Breadcrumb) {
	if tc == nil {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if b.Timestamp.IsZero() {
		b.Timestamp = time.Now()
	}
	tc.Breadcrumbs = append(tc.Breadcrumbs, b)
	if len(tc.Breadcrumbs) > 100 {
		tc.Breadcrumbs = tc.Breadcrumbs[len(tc.Breadcrumbs)-100:]
	}
}

func (tc *TraceContext) SetUser(u User) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.User = &u
}

// Traceparent formats this trace context into a W3C Trace Context traceparent header string.
func (tc *TraceContext) Traceparent() string {
	if tc == nil {
		return ""
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return fmt.Sprintf("00-%s-%s-01", tc.TraceID, tc.SpanID)
}

// NewTraceContext initializes a trace context. It parses incoming W3C traceparent headers,
// or falls back to preserving custom trace identifiers or generating a fresh 32-char hex trace ID.
func NewTraceContext(headerOrID string) *TraceContext {
	traceID, parentSpanID, ok := ParseTraceparent(headerOrID)
	if !ok {
		if headerOrID != "" {
			traceID = headerOrID
		} else {
			traceID = GenerateTraceID()
		}
		parentSpanID = ""
	}
	spanID := GenerateSpanID()

	return &TraceContext{
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		StartTime:    time.Now(),
		Spans:        make([]Span, 0),
	}
}

func WithTraceContext(ctx context.Context, tc *TraceContext) context.Context {
	return context.WithValue(ctx, traceContextKey, tc)
}

func GetTraceContext(ctx context.Context) *TraceContext {
	if ctx == nil {
		return nil
	}
	if tc, ok := ctx.Value(traceContextKey).(*TraceContext); ok {
		return tc
	}
	return nil
}

// ShouldSample decides, for one incoming request, whether it should be traced at all -
// framework adapters (beacongin, beaconfiber, beaconhttp) call this before creating a trace
// context, so an unsampled request never queues a trace or makes an ingest call.
func ShouldSample() bool {
	c := GetClient()
	if c == nil || c.cfg.SampleRate >= 1.0 {
		return true
	}
	return rand.Float64() < c.cfg.SampleRate
}

// TraceID returns the current request's trace ID, or "" if this context isn't inside
// a Beacon-instrumented request.
func TraceID(ctx context.Context) string {
	tc := GetTraceContext(ctx)
	if tc == nil {
		return ""
	}
	return tc.TraceID
}

// SpanID returns the current request's root span ID, or "" if not inside a Beacon-instrumented request.
func SpanID(ctx context.Context) string {
	tc := GetTraceContext(ctx)
	if tc == nil {
		return ""
	}
	return tc.SpanID
}

// Traceparent returns the W3C traceparent header for the current request, or "".
func Traceparent(ctx context.Context) string {
	tc := GetTraceContext(ctx)
	if tc == nil {
		return ""
	}
	return tc.Traceparent()
}

// InjectTraceHeaders injects W3C traceparent headers into an outgoing HTTP request Header.
func InjectTraceHeaders(ctx context.Context, h http.Header) {
	if tp := Traceparent(ctx); tp != "" && h != nil {
		h.Set("traceparent", tp)
	}
}

// AddBreadcrumb records a breadcrumb (log, database query, HTTP call, UI action)
// into the current request's trace context.
func AddBreadcrumb(ctx context.Context, b Breadcrumb) {
	if tc := GetTraceContext(ctx); tc != nil {
		tc.AddBreadcrumb(b)
	}
}

// AddJobSpan records a background job or queue execution span into the active trace context.
func AddJobSpan(ctx context.Context, jobName, queue string, durationMs, waitMs float64, tags map[string]string) {
	if tc := GetTraceContext(ctx); tc != nil {
		tc.AddJobSpan(jobName, queue, durationMs, waitMs, tags)
	}
}

var sensitiveHeaderNames = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"api-key":             true,
	"proxy-authorization": true,
	"x-auth-token":        true,
	"x-csrf-token":        true,
	"x-xsrf-token":        true,
	"token":               true,
	"secret":              true,
	"password":            true,
}

// SanitizeHeaders redacts sensitive HTTP headers (auth tokens, session cookies, api keys)
// ensuring no credentials or PII are transmitted in telemetry.
func SanitizeHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	sanitized := make(map[string]string, len(headers))
	for k, v := range headers {
		lowerK := strings.ToLower(k)
		if sensitiveHeaderNames[lowerK] ||
			strings.Contains(lowerK, "token") ||
			strings.Contains(lowerK, "secret") ||
			(strings.Contains(lowerK, "key") && lowerK != "key") {
			sanitized[lowerK] = "[Filtered]"
		} else {
			sanitized[lowerK] = v
		}
	}
	return sanitized
}
