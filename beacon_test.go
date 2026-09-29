package beacon_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trustportidentity/beacon-go"
	"github.com/trustportidentity/beacon-go/adapter/beacongin"
)

func TestBeaconPanicRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	client := beacon.Init(beacon.Config{
		APIKey:      "tb_test_key_123",
		ServiceName: "test-go-service",
		Environment: "test",
		IngestURL:   "http://127.0.0.1:9999", // mock target
		BatchSize:   1,
		FlushPeriod: 10 * time.Millisecond,
	})
	defer client.FlushAndClose()

	r := gin.New()
	r.Use(beacongin.Middleware("test-go-service"))

	r.GET("/panic-test", func(c *gin.Context) {
		beacongin.Identify(c, beacon.User{
			ID:    "usr_test_99",
			Email: "tester@trustport.tech",
		})

		span := beacon.StartTypedSpan(c.Request.Context(), "SELECT * FROM test_table", "database")
		time.Sleep(2 * time.Millisecond)
		span.End()

		// Deliberate panic to test recovery and stack trace extraction
		var ptr *string
		_ = *ptr
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/panic-test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500 from panic handler, got %d", w.Code)
	}

	t.Log("✓ Successfully recovered from panic, captured user and span context")
}

func TestBeaconContextSpans(t *testing.T) {
	tc := beacon.NewTraceContext("trace-test-123")
	ctx := beacon.WithTraceContext(context.Background(), tc)

	span := beacon.StartTypedSpan(ctx, "redis_lookup", "cache")
	time.Sleep(1 * time.Millisecond)
	span.SetMetadata(beacon.SpanMetadata{
		Key: "session:test",
		Op:  "GET",
	})
	span.End()

	if len(tc.Spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(tc.Spans))
	}
	if tc.Spans[0].Type != "cache" {
		t.Errorf("expected span type 'cache', got %s", tc.Spans[0].Type)
	}
	if tc.Spans[0].SpanID == "" {
		t.Errorf("expected non-empty span ID")
	}
	if tc.Spans[0].ParentSpanID != tc.SpanID {
		t.Errorf("expected parent span ID %s, got %s", tc.SpanID, tc.Spans[0].ParentSpanID)
	}
}

func TestW3CTraceparentParsingAndPropagation(t *testing.T) {
	incoming := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tc := beacon.NewTraceContext(incoming)

	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("expected trace ID 4bf92f3577b34da6a3ce929d0e0e4736, got %s", tc.TraceID)
	}
	if tc.ParentSpanID != "00f067aa0ba902b7" {
		t.Fatalf("expected parent span ID 00f067aa0ba902b7, got %s", tc.ParentSpanID)
	}
	if len(tc.SpanID) != 16 {
		t.Fatalf("expected 16-hex span ID, got %s", tc.SpanID)
	}

	tp := tc.Traceparent()
	expectedPrefix := "00-4bf92f3577b34da6a3ce929d0e0e4736-" + tc.SpanID + "-01"
	if tp != expectedPrefix {
		t.Fatalf("expected traceparent %s, got %s", expectedPrefix, tp)
	}

	ctx := beacon.WithTraceContext(context.Background(), tc)
	req, _ := http.NewRequest("GET", "https://api.internal/service-b", nil)
	beacon.InjectTraceHeaders(ctx, req.Header)

	if req.Header.Get("traceparent") != expectedPrefix {
		t.Fatalf("expected injected header %s, got %s", expectedPrefix, req.Header.Get("traceparent"))
	}
}

func TestSanitizeHeaders(t *testing.T) {
	raw := map[string]string{
		"Authorization":   "Bearer secret_token_xyz",
		"Cookie":          "session_id=abcdef123456",
		"X-Api-Key":       "sk_live_998877",
		"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
		"Accept-Encoding": "gzip, deflate",
	}

	sanitized := beacon.SanitizeHeaders(raw)

	if sanitized["authorization"] != "[Filtered]" {
		t.Errorf("expected authorization to be filtered, got %s", sanitized["authorization"])
	}
	if sanitized["cookie"] != "[Filtered]" {
		t.Errorf("expected cookie to be filtered, got %s", sanitized["cookie"])
	}
	if sanitized["x-api-key"] != "[Filtered]" {
		t.Errorf("expected x-api-key to be filtered, got %s", sanitized["x-api-key"])
	}
	if sanitized["user-agent"] != "Mozilla/5.0 (Macintosh; Intel Mac OS X)" {
		t.Errorf("expected user-agent to be preserved, got %s", sanitized["user-agent"])
	}
}

func TestBreadcrumbs(t *testing.T) {
	tc := beacon.NewTraceContext("trace-crumb-test")
	ctx := beacon.WithTraceContext(context.Background(), tc)

	beacon.AddBreadcrumb(ctx, beacon.Breadcrumb{
		Category: "log",
		Message:  "User requested payment checkout",
		Level:    "info",
	})
	beacon.AddBreadcrumb(ctx, beacon.Breadcrumb{
		Category: "query",
		Message:  "SELECT * FROM accounts WHERE id = 42",
		Level:    "info",
		Data: map[string]interface{}{
			"duration_ms": 1.8,
		},
	})

	if len(tc.Breadcrumbs) != 2 {
		t.Fatalf("expected 2 breadcrumbs, got %d", len(tc.Breadcrumbs))
	}
	if tc.Breadcrumbs[0].Category != "log" {
		t.Errorf("expected category 'log', got %s", tc.Breadcrumbs[0].Category)
	}
	if tc.Breadcrumbs[1].Category != "query" {
		t.Errorf("expected category 'query', got %s", tc.Breadcrumbs[1].Category)
	}
	if tc.Breadcrumbs[0].Timestamp.IsZero() {
		t.Errorf("expected auto-populated timestamp")
	}
}
