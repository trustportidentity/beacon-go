package beaconfiber

import (
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/trustportidentity/beacon-go"
)

// Middleware creates a Fiber v2 compatible middleware for Beacon APM.
func Middleware(serviceName string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		rawTraceparent := c.Get("traceparent")
		tc := beacon.NewTraceContext(rawTraceparent)
		ctx := beacon.WithTraceContext(c.UserContext(), tc)
		c.SetUserContext(ctx)

		c.Set("traceparent", tc.Traceparent())

		var exc *beacon.Exception
		var hasExc bool
		var handlerErr error

		func() {
			defer func() {
				if r := recover(); r != nil {
					hasExc = true
					rawStack := string(debug.Stack())
					exc = &beacon.Exception{
						Type:       fmt.Sprintf("%v", r),
						Message:    fmt.Sprintf("panic: %v", r),
						Handled:    false,
						Stacktrace: parseStack(rawStack),
					}
					c.Status(fiber.StatusInternalServerError)
				}
			}()
			handlerErr = c.Next()
		}()

		statusCode := c.Response().StatusCode()
		if handlerErr != nil && !hasExc {
			hasExc = true
			exc = &beacon.Exception{
				Type:    "HandlerError",
				Message: handlerErr.Error(),
				Handled: true,
			}
		}

		durationMs := float64(time.Since(start).Microseconds()) / 1000.0

		// Exceptions are always sent regardless of SampleRate - sampling controls ingest
		// volume for routine traffic, never error visibility.
		if client := beacon.GetClient(); client != nil && (hasExc || beacon.ShouldSample()) {
			rawHeaders := make(map[string]string)
			c.Request().Header.VisitAll(func(k, v []byte) {
				rawHeaders[strings.ToLower(string(k))] = string(v)
			})
			headers := beacon.SanitizeHeaders(rawHeaders)

			route := c.Route().Path
			if route == "" {
				route = string(c.Request().URI().Path())
			}

			tr := &beacon.TraceEvent{
				ID:          tc.TraceID,
				ServiceName: serviceName,
				TraceID:     tc.TraceID,
				ParentSpan:  tc.ParentSpanID,
				Timestamp:   start,
				DurationMs:  durationMs,
				User:        tc.User,
				Request: &beacon.RequestContext{
					Method:     c.Method(),
					Route:      route,
					URL:        c.OriginalURL(),
					StatusCode: statusCode,
					Headers:    headers,
					ClientIP:   c.IP(),
				},
				Spans:        tc.Spans,
				HasException: hasExc,
				Exception:    exc,
			}
			client.SendTrace(tr)
		}

		return handlerErr
	}
}

// Identify attaches user identity to the current request's trace.
func Identify(c *fiber.Ctx, user beacon.User) {
	tc := beacon.GetTraceContext(c.UserContext())
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
