package beacon

import (
	"context"
	"fmt"
	"time"
)

type CustomSpan struct {
	tc        *TraceContext
	spanID    string
	parentID  string
	spanType  string
	name      string
	startTime time.Time
	metadata  *SpanMetadata
	tags      map[string]string
}

// StartSpan begins a child span of the current request's trace. spanType defaults to
// "custom"; use SetMetadata instead for a well-known database/cache span.
func StartSpan(ctx context.Context, name string) *CustomSpan {
	tc := GetTraceContext(ctx)
	parentID := ""
	if tc != nil {
		parentID = tc.SpanID
	}
	return &CustomSpan{
		tc:        tc,
		spanID:    GenerateSpanID(),
		parentID:  parentID,
		spanType:  "custom",
		name:      name,
		startTime: time.Now(),
	}
}

// StartTypedSpan is StartSpan with an explicit span type ("database", "cache", "http",
// "job", "middleware", "custom").
func StartTypedSpan(ctx context.Context, name, spanType string) *CustomSpan {
	s := StartSpan(ctx, name)
	s.spanType = spanType
	return s
}

func (s *CustomSpan) SetMetadata(m SpanMetadata) *CustomSpan {
	s.metadata = &m
	return s
}

// SetTag attaches a free-form key/value tag to this span, visible in the trace
// waterfall. Chainable.
func (s *CustomSpan) SetTag(key string, value any) *CustomSpan {
	if s.tags == nil {
		s.tags = make(map[string]string)
	}
	s.tags[key] = fmt.Sprintf("%v", value)
	return s
}

func (s *CustomSpan) SpanID() string {
	return s.spanID
}

func (s *CustomSpan) End() {
	if s.tc == nil {
		return
	}
	durationMs := float64(time.Since(s.startTime).Microseconds()) / 1000.0
	startMs := float64(s.startTime.Sub(s.tc.StartTime).Microseconds()) / 1000.0
	if startMs < 0 {
		startMs = 0
	}

	s.tc.AddSpan(Span{
		SpanID:       s.spanID,
		ParentSpanID: s.parentID,
		Type:         s.spanType,
		Name:         s.name,
		StartMs:      startMs,
		DurationMs:   durationMs,
		Metadata:     s.metadata,
		Tags:         s.tags,
	})
}
