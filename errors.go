package beacon

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
)

// maxErrorBodyBytes caps how much of a 5xx response body adapters keep to describe the failure.
const maxErrorBodyBytes = 2048

// CaptureError attaches a handled error to the request's trace, with the stack at the call site,
// so a handler that recovers from an error and responds 500 still shows what actually went wrong.
// The last captured error wins. It is a no-op outside a traced request or for a nil error.
func CaptureError(ctx context.Context, err error) {
	GetTraceContext(ctx).captureError(err, 4)
}

// CaptureError records err as this trace's exception; see the package-level CaptureError.
func (tc *TraceContext) CaptureError(err error) {
	tc.captureError(err, 4)
}

// captureError skips runtime.Callers, callerStack, captureError and its exported caller, so the
// stack starts at the application code that reported the error.
func (tc *TraceContext) captureError(err error, skip int) {
	if tc == nil || err == nil {
		return
	}
	exc := &Exception{
		Type:       strings.TrimPrefix(fmt.Sprintf("%T", err), "*"),
		Message:    err.Error(),
		Handled:    true,
		Stacktrace: callerStack(skip),
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.Exception = exc
}

// CapturedException returns the error recorded with CaptureError, if any.
func (tc *TraceContext) CapturedException() *Exception {
	if tc == nil {
		return nil
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.Exception
}

// ResolveException picks what a finished request reports as its exception: a panic first, then an
// error captured with CaptureError, then - for a 5xx with neither - one built from the response the
// handler sent, so a server error is never recorded without any detail.
func ResolveException(tc *TraceContext, panicExc *Exception, status int, method, path string, body []byte) *Exception {
	if panicExc != nil {
		return panicExc
	}
	if exc := tc.CapturedException(); exc != nil {
		return exc
	}
	if status < 500 {
		return nil
	}
	return ServerErrorException(status, method, path, body)
}

// ServerErrorException describes a 5xx response that carried no exception. Type names the status
// and the handler's error message, so each distinct failure groups into its own issue.
func ServerErrorException(status int, method, path string, body []byte) *Exception {
	msg := errorMessageFromBody(body)
	typ := fmt.Sprintf("HTTP %d", status)
	message := fmt.Sprintf("%s %s responded %d", method, path, status)
	if msg != "" {
		typ += ": " + truncate(msg, 120)
		message += ": " + msg
	}
	return &Exception{Type: typ, Message: message, Handled: true}
}

// errorMessageFromBody pulls the error text out of a response body: the usual JSON error fields
// when it is JSON, otherwise the trimmed text itself.
func errorMessageFromBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return ""
	}
	var obj map[string]any
	if json.Unmarshal([]byte(text), &obj) == nil {
		for _, key := range []string{"error", "message", "detail", "title"} {
			switch v := obj[key].(type) {
			case string:
				if v != "" {
					return truncate(v, 500)
				}
			case map[string]any:
				if m, ok := v["message"].(string); ok && m != "" {
					return truncate(m, 500)
				}
			}
		}
	}
	return truncate(text, 500)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ErrorBodyBuffer keeps the start of a response body once the status is known to be a 5xx, for
// ServerErrorException. Adapters feed it every write; it ignores bodies of non-error responses.
type ErrorBodyBuffer struct {
	buf []byte
}

// Write records up to maxErrorBodyBytes of p when status is 500 or above.
func (b *ErrorBodyBuffer) Write(status int, p []byte) {
	if status < 500 || len(b.buf) >= maxErrorBodyBytes {
		return
	}
	room := maxErrorBodyBytes - len(b.buf)
	if len(p) > room {
		p = p[:room]
	}
	b.buf = append(b.buf, p...)
}

// Bytes returns what was kept.
func (b *ErrorBodyBuffer) Bytes() []byte { return b.buf }

func callerStack(skip int) []StackFrame {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(skip, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	var out []StackFrame
	for {
		f, more := frames.Next()
		if f.File != "" {
			out = append(out, StackFrame{File: f.File, Line: f.Line, Function: f.Function})
		}
		if !more {
			break
		}
	}
	return out
}
