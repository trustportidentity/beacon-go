package beaconhttp

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/trustportidentity/beacon-go"
)

type statusLoggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusLoggingResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// Handler wraps next using the service name configured in beacon.Init. Use Middleware
// instead if you need to name this handler differently from the client's default.
func Handler(next http.Handler) http.Handler {
	serviceName := ""
	if c := beacon.GetClient(); c != nil {
		serviceName = c.ServiceName()
	}
	return Middleware(serviceName)(next)
}

// Middleware creates a standard net/http and Chi compatible middleware for Beacon APM.
func Middleware(serviceName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rawTraceparent := r.Header.Get("traceparent")
			tc := beacon.NewTraceContext(rawTraceparent)
			ctx := beacon.WithTraceContext(r.Context(), tc)
			r = r.WithContext(ctx)

			ww := &statusLoggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			ww.Header().Set("traceparent", tc.Traceparent())

			var exc *beacon.Exception
			var hasExc bool

			defer func() {
				durationMs := float64(time.Since(start).Microseconds()) / 1000.0

				if rec := recover(); rec != nil {
					hasExc = true
					ww.statusCode = http.StatusInternalServerError

					rawStack := string(debug.Stack())
					frames := parseStack(rawStack)

					exc = &beacon.Exception{
						Type:       fmt.Sprintf("%v", rec),
						Message:    fmt.Sprintf("panic: %v", rec),
						Handled:    false,
						Stacktrace: frames,
					}
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}

				client := beacon.GetClient()
				// Exceptions are always sent regardless of SampleRate - sampling controls
				// ingest volume for routine traffic, never error visibility.
				if client != nil && (hasExc || beacon.ShouldSample()) {
					rawHeaders := make(map[string]string)
					for k, v := range r.Header {
						if len(v) > 0 {
							rawHeaders[strings.ToLower(k)] = v[0]
						}
					}
					headers := beacon.SanitizeHeaders(rawHeaders)

					tr := &beacon.TraceEvent{
						ID:          tc.TraceID,
						ServiceName: serviceName,
						TraceID:     tc.TraceID,
						ParentSpan:  tc.ParentSpanID,
						Timestamp:   start,
						DurationMs:  durationMs,
						User:        tc.User,
						Request: &beacon.RequestContext{
							Method:     r.Method,
							Route:      r.URL.Path,
							URL:        r.URL.String(),
							StatusCode: ww.statusCode,
							Headers:    headers,
							ClientIP:   r.RemoteAddr,
						},
						Spans:        tc.Spans,
						HasException: hasExc,
						Exception:    exc,
					}

					client.SendTrace(tr)
				}
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

func parseStack(raw string) []beacon.StackFrame {
	lines := strings.Split(raw, "\n")
	var frames []beacon.StackFrame

	for i := 0; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "/") || strings.Contains(line, ".go:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				file := strings.TrimSpace(parts[0])
				lineNumStr := strings.Fields(parts[1])[0]
				lineNum, _ := strconv.Atoi(lineNumStr)

				fn := "unknown"
				if i > 0 {
					fn = strings.TrimSpace(lines[i-1])
				}

				frames = append(frames, beacon.StackFrame{
					File:     file,
					Line:     lineNum,
					Function: fn,
				})
			}
		}
	}

	return frames
}
