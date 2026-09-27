package beacon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

// SpanMetadata carries well-known fields for infrastructure spans (database/cache calls).
// For anything else, use Span.Tags via CustomSpan.SetTag.
type SpanMetadata struct {
	Driver       string `json:"driver,omitempty"`
	Table        string `json:"table,omitempty"`
	RowsReturned int    `json:"rows_returned,omitempty"`
	Hit          *bool  `json:"hit,omitempty"`
	Key          string `json:"key,omitempty"`
	Op           string `json:"op,omitempty"`
	StatusCode   int    `json:"status_code,omitempty"`
}

type Span struct {
	Type       string            `json:"type"` // database, cache, http, job, middleware, custom
	Name       string            `json:"name"`
	StartMs    float64           `json:"start_ms"`
	DurationMs float64           `json:"duration_ms"`
	Metadata   *SpanMetadata     `json:"metadata,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
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
	Timestamp    time.Time       `json:"timestamp"`
	DurationMs   float64         `json:"duration_ms"`
	User         *User           `json:"user,omitempty"`
	Request      *RequestContext `json:"request,omitempty"`
	Spans        []Span          `json:"spans"`
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

type TraceContext struct {
	mu        sync.Mutex
	TraceID   string
	StartTime time.Time
	User      *User
	Spans     []Span
}

func (tc *TraceContext) AddSpan(s Span) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.Spans = append(tc.Spans, s)
}

func (tc *TraceContext) SetUser(u User) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.User = &u
}

func NewTraceContext(traceID string) *TraceContext {
	if traceID == "" {
		traceID = uuid.New().String()
	}
	return &TraceContext{
		TraceID:   traceID,
		StartTime: time.Now(),
		Spans:     make([]Span, 0),
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

// TraceID returns the current request's trace ID, or "" if this context isn't inside
// a Beacon-instrumented request.
func TraceID(ctx context.Context) string {
	tc := GetTraceContext(ctx)
	if tc == nil {
		return ""
	}
	return tc.TraceID
}
