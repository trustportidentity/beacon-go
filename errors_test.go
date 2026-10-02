package beacon_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trustportidentity/beacon-go"
	"github.com/trustportidentity/beacon-go/adapter/beaconhttp"
)

// sendAndCollect runs one request through beaconhttp with a fake ingest server and returns the
// trace it sent.
func sendAndCollect(t *testing.T, path string, handler http.HandlerFunc) beacon.TraceEvent {
	t.Helper()
	var mu sync.Mutex
	var got []beacon.TraceEvent
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []beacon.TraceEvent
		_ = json.NewDecoder(r.Body).Decode(&batch)
		mu.Lock()
		got = append(got, batch...)
		mu.Unlock()
	}))
	defer ingest.Close()

	client := beacon.Init(beacon.Config{
		APIKey:      "tb_test_key",
		ServiceName: "svc",
		IngestURL:   ingest.URL,
		BatchSize:   1,
		FlushPeriod: 5 * time.Millisecond,
	})
	defer client.FlushAndClose()

	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("User-Agent", "beacon-test")
	beaconhttp.Middleware("svc")(handler).ServeHTTP(httptest.NewRecorder(), req)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("expected 1 trace, got %d", len(got))
	}
	return got[0]
}

func TestServerErrorWithoutPanicReportsResponseMessage(t *testing.T) {
	tr := sendAndCollect(t, "/legacy/ground-rent?file_no=ENP-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"Failed to load ground rent data"}`))
	})
	if !tr.HasException || tr.Exception == nil {
		t.Fatal("a 500 response should be reported as an exception")
	}
	if tr.Exception.Type != "HTTP 500: Failed to load ground rent data" {
		t.Errorf("unexpected type %q", tr.Exception.Type)
	}
	if !strings.Contains(tr.Exception.Message, "GET /legacy/ground-rent responded 500") {
		t.Errorf("unexpected message %q", tr.Exception.Message)
	}
	if tr.Request == nil || tr.Request.Headers["user-agent"] != "beacon-test" {
		t.Errorf("request headers missing: %+v", tr.Request)
	}
}

func TestCaptureErrorReportsRealErrorAndStack(t *testing.T) {
	tr := sendAndCollect(t, "/thing", func(w http.ResponseWriter, r *http.Request) {
		beacon.CaptureError(r.Context(), errors.New("pq: relation \"ground_rent\" does not exist"))
		http.Error(w, "Failed to load", http.StatusInternalServerError)
	})
	if tr.Exception == nil || tr.Exception.Message != `pq: relation "ground_rent" does not exist` {
		t.Fatalf("captured error not reported: %+v", tr.Exception)
	}
	if tr.Exception.Type != "errors.errorString" || !tr.Exception.Handled {
		t.Errorf("unexpected type/handled: %q %v", tr.Exception.Type, tr.Exception.Handled)
	}
	if len(tr.Exception.Stacktrace) == 0 || !strings.Contains(tr.Exception.Stacktrace[0].Function, "TestCaptureErrorReportsRealErrorAndStack") {
		t.Errorf("stack should start in the handler, got %+v", tr.Exception.Stacktrace)
	}
}

func TestSuccessfulRequestHasNoException(t *testing.T) {
	tr := sendAndCollect(t, "/ok", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fine"))
	})
	if tr.HasException || tr.Exception != nil {
		t.Fatalf("200 response must not carry an exception: %+v", tr.Exception)
	}
}
