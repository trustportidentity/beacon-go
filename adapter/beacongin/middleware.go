package beacongin

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/trustportidentity/beacon-go"
)

func Middleware(serviceName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		rawTraceparent := c.GetHeader("traceparent")
		tc := beacon.NewTraceContext(rawTraceparent)
		ctx := beacon.WithTraceContext(c.Request.Context(), tc)
		c.Request = c.Request.WithContext(ctx)

		c.Header("traceparent", tc.Traceparent())

		defer func() {
			durationMs := float64(time.Since(start).Microseconds()) / 1000.0

			var exc *beacon.Exception
			var hasExc bool
			statusCode := c.Writer.Status()

			if r := recover(); r != nil {
				hasExc = true
				statusCode = http.StatusInternalServerError

				rawStack := string(debug.Stack())
				frames := parseStack(rawStack)

				exc = &beacon.Exception{
					Type:       fmt.Sprintf("%v", r),
					Message:    fmt.Sprintf("panic: %v", r),
					Handled:    false,
					Stacktrace: frames,
				}

				c.AbortWithStatus(http.StatusInternalServerError)
			} else if len(c.Errors) > 0 {
				hasExc = true
				lastErr := c.Errors.Last()
				exc = &beacon.Exception{
					Type:    "HandlerError",
					Message: lastErr.Error(),
					Handled: true,
				}
			}

			client := beacon.GetClient()
			// Exceptions are always sent regardless of SampleRate - sampling controls
			// ingest volume for routine traffic, never error visibility.
			if client != nil && (hasExc || beacon.ShouldSample()) {
				route := c.FullPath()
				if route == "" {
					route = c.Request.URL.Path
				}

				rawHeaders := make(map[string]string)
				for k, v := range c.Request.Header {
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
						Method:     c.Request.Method,
						Route:      route,
						URL:        c.Request.URL.String(),
						StatusCode: statusCode,
						Headers:    headers,
						ClientIP:   c.ClientIP(),
					},
					Spans:        tc.Spans,
					HasException: hasExc,
					Exception:    exc,
				}

				client.SendTrace(tr)
			}
		}()

		c.Next()
	}
}

func Identify(c *gin.Context, user beacon.User) {
	tc := beacon.GetTraceContext(c.Request.Context())
	if tc != nil {
		tc.SetUser(user)
	}
}

func parseStack(raw string) []beacon.StackFrame {
	lines := strings.Split(raw, "\n")
	var frames []beacon.StackFrame

	for i := 0; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "/") || strings.Contains(line, ".go:") {
			// Contains file & line
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
