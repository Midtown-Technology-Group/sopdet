package ingest

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

var noSleep = func(time.Duration) {}
var noJitter = func(time.Duration) time.Duration { return 0 }

func TestEndpointRequiresHTTPSOrLoopback(t *testing.T) {
	for _, endpoint := range []string{"http://example.invalid/ingest", "ftp://example.invalid/ingest", "https://user:pass@example.invalid/ingest"} {
		if err := validateEndpoint(endpoint); err == nil {
			t.Errorf("accepted unsafe endpoint %q", endpoint)
		}
	}
	for _, endpoint := range []string{"https://example.invalid/ingest", "http://127.0.0.1:8080/ingest", "http://localhost/ingest"} {
		if err := validateEndpoint(endpoint); err != nil {
			t.Errorf("rejected safe endpoint %q: %v", endpoint, err)
		}
	}
}

func TestIngestRefusesRedirectBeforeSendingKey(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/target")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)
	env := testEnvelope()
	res, err := Send(env, Options{
		Endpoint: source.URL, APIKey: "synthetic-key", ScanID: env.ScanID,
		MaxRetries: 1, Sleep: noSleep, Jitter: noJitter,
	})
	if err != nil || res.Delivered {
		t.Fatalf("redirected ingest should fail delivery: %+v, %v", res, err)
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect target received inventory or key")
	}
}

type received struct {
	payload   string
	encoding  string
	chunkIdx  int
	chunkCnt  int
	hasHeader bool
}

func decodeEnvelope(t *testing.T, payload, encoding string) *schema.Envelope {
	t.Helper()
	raw := []byte(payload)
	if encoding == "gzip+base64" {
		b, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			t.Fatalf("base64: %v", err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("gzip: %v", err)
		}
		raw, err = io.ReadAll(zr)
		if err != nil {
			t.Fatalf("read gzip: %v", err)
		}
	}
	var env schema.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return &env
}

func testEnvelope() *schema.Envelope {
	names := []string{"host", "os", "software", "services", "drivers", "volumes"}
	entities := map[string]any{}
	for _, n := range names {
		recs := []schema.Record{}
		for i := 0; i < 8; i++ {
			recs = append(recs, schema.Record{"key": n, "idx": i, "payload": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"})
		}
		entities[n] = schema.BuildEntity(recs, "2026-01-01T00:00:00Z")
	}
	return &schema.Envelope{
		SchemaVersion: 2,
		ScanID:        "33333333-3333-3333-3333-333333333333",
		Action:        schema.ActionSnapshot,
		HostIdentifier: schema.HostIdentifier{
			DeviceID:       "00000000-0000-4000-8000-0000000000aa",
			DeviceIDSource: "machine_guid",
			InstanceID:     "00000000-0000-4000-8000-0000000000cc",
			Hostname:       "TEST",
		},
		CalendarTime: "2026-01-01T00:00:00Z",
		UnixTime:     1767225600,
		Agent:        schema.Agent{Name: "sopdet", Version: "test", OS: "linux", Arch: "amd64", Profile: "full"},
		Truncated:    []string{},
		EntityErrors: map[string]schema.EntityError{},
		Entities:     entities,
	}
}

const successReply = `{"execution_id":"00000000-0000-4000-8000-000000000001","status":"Success"}`

func recorder(t *testing.T, failFirst int, status int) (*httptest.Server, *[]received, *int) {
	t.Helper()
	return recorderWith(t, failFirst, status, successReply)
}

// recorderWith answers non-failed requests with status and, for 2xx, the
// given Bifrost endpoint response body.
func recorderWith(t *testing.T, failFirst int, status int, reply string) (*httptest.Server, *[]received, *int) {
	t.Helper()
	var mu sync.Mutex
	got := []received{}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls <= failFirst {
			w.WriteHeader(500)
			return
		}
		var b struct {
			Payload         string  `json:"payload"`
			ContentEncoding *string `json:"content_encoding"`
			ChunkIndex      int     `json:"chunk_index"`
			ChunkCount      int     `json:"chunk_count"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Errorf("decode body: %v", err)
		}
		enc := ""
		if b.ContentEncoding != nil {
			enc = *b.ContentEncoding
		}
		got = append(got, received{payload: b.Payload, encoding: enc, chunkIdx: b.ChunkIndex, chunkCnt: b.ChunkCount, hasHeader: r.Header.Get("X-Bifrost-Key") != ""})
		w.WriteHeader(status)
		if status >= 200 && status < 300 && reply != "" {
			_, _ = io.WriteString(w, reply)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &calls
}

func TestSendChunksAndCompresses(t *testing.T) {
	srv, got, _ := recorder(t, 0, 200)
	env := testEnvelope()
	res, err := Send(env, Options{
		Endpoint: srv.URL, APIKey: "k", Compress: true, ChunkBytes: 400,
		MaxRetries: 1, ScanID: env.ScanID, Sleep: noSleep, Jitter: noJitter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Delivered {
		t.Fatalf("not delivered: %+v", res)
	}
	if res.Chunks < 2 {
		t.Fatalf("expected multiple chunks, got %d", res.Chunks)
	}
	seen := map[string]bool{}
	for _, r := range *got {
		if r.encoding != "gzip+base64" {
			t.Fatalf("expected compressed chunk, got %q", r.encoding)
		}
		if !r.hasHeader {
			t.Fatal("missing X-Bifrost-Key header")
		}
		chunkEnv := decodeEnvelope(t, r.payload, r.encoding)
		if chunkEnv.Chunk == nil || chunkEnv.Chunk.Count != res.Chunks {
			t.Fatalf("chunk metadata wrong: %+v", chunkEnv.Chunk)
		}
		for name := range chunkEnv.Entities {
			seen[name] = true
		}
	}
	if len(seen) != len(env.Entities) {
		t.Fatalf("entity coverage %d != %d", len(seen), len(env.Entities))
	}
}

func TestRetryThenSuccess(t *testing.T) {
	srv, _, calls := recorder(t, 2, 200)
	env := testEnvelope()
	res, err := Send(env, Options{
		Endpoint: srv.URL, Compress: false, ChunkBytes: 0,
		MaxRetries: 4, ScanID: env.ScanID, Sleep: noSleep, Jitter: noJitter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Delivered || *calls != 3 {
		t.Fatalf("expected success on 3rd attempt, delivered=%v calls=%d", res.Delivered, *calls)
	}
}

func TestSpoolDoesNotReplayAcrossEndpoints(t *testing.T) {
	spool := filepath.Join(t.TempDir(), "spool")
	bad, _, _ := recorder(t, 1_000, 503)
	env := testEnvelope()
	res, err := Send(env, Options{
		Endpoint: bad.URL, Compress: true, ChunkBytes: 400,
		MaxRetries: 1, SpoolDir: spool, ScanID: env.ScanID, Sleep: noSleep, Jitter: noJitter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Delivered || res.Spooled == 0 {
		t.Fatalf("expected spooled failure, got %+v", res)
	}

	good, got, _ := recorder(t, 0, 200)
	res2, err := Send(env, Options{
		Endpoint: good.URL, Compress: true, ChunkBytes: 400,
		MaxRetries: 1, SpoolDir: spool, ScanID: env.ScanID, Sleep: noSleep, Jitter: noJitter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Delivered || res2.Spooled != 0 {
		t.Fatalf("expected new endpoint delivery, got %+v (received %d)", res2, len(*got))
	}
	if len(*got) != res2.Chunks {
		t.Fatalf("new endpoint received %d chunks; want only %d current chunks", len(*got), res2.Chunks)
	}
	old, err := os.ReadDir(scopedSpoolDir(spool, bad.URL, ""))
	if err != nil || len(old) == 0 {
		t.Fatalf("old endpoint spool should remain quarantined: %v", err)
	}
}

func TestSpoolScopeChangesWithCredentialAndImplementation(t *testing.T) {
	base := filepath.Join(t.TempDir(), "spool")
	a := scopedSpoolDir(base, "https://example.invalid/ingest", "synthetic-key-a")
	b := scopedSpoolDir(base, "https://example.invalid/ingest", "synthetic-key-b")
	if a == b || a == base || b == base {
		t.Fatal("spool scope did not bind credential identity")
	}
	if scopedSpoolDir(base, "https://other.invalid/ingest", "synthetic-key-a") == a {
		t.Fatal("spool scope did not bind endpoint")
	}
}

func TestUnconfirmedWorkflowOutcomesAreNotDeliveredRetriedOrSpooled(t *testing.T) {
	cases := map[string]string{
		"failed":        `{"execution_id":"00000000-0000-4000-8000-000000000002","status":"Failed","error":"synthetic"}`,
		"timeout":       `{"execution_id":"00000000-0000-4000-8000-000000000003","status":"Timeout"}`,
		"async pending": `{"execution_id":"00000000-0000-4000-8000-000000000004","status":"Pending"}`,
		"with errors":   `{"status":"CompletedWithErrors"}`,
		"empty body":    ``,
		"no status":     `{"execution_id":"00000000-0000-4000-8000-000000000005"}`,
		"not json":      `<html>ok</html>`,
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			spool := filepath.Join(t.TempDir(), "spool")
			srv, _, calls := recorderWith(t, 0, http.StatusOK, reply)
			env := testEnvelope()
			res, err := Send(env, Options{
				Endpoint: srv.URL, ChunkBytes: 0, MaxRetries: 4, SpoolDir: spool,
				ScanID: env.ScanID, Sleep: noSleep, Jitter: noJitter,
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.Delivered {
				t.Fatalf("unconfirmed outcome reported as delivered: %+v", res)
			}
			if *calls != 1 {
				t.Fatalf("a 2xx answer must not be retried; calls=%d", *calls)
			}
			if res.Spooled != 0 {
				t.Fatalf("a 2xx answer must not be spooled for replay; spooled=%d", res.Spooled)
			}
			if len(res.Unconfirmed) != 1 {
				t.Fatalf("expected one unconfirmed chunk, got %q", res.Unconfirmed)
			}
			if strings.Contains(res.Unconfirmed[0], "synthetic") {
				t.Fatalf("workflow error text leaked into the report: %q", res.Unconfirmed[0])
			}
		})
	}
}

func TestSpooledChunkAnsweredWithoutSuccessIsDroppedNotReplayed(t *testing.T) {
	var phase atomic.Int32 // 0: unavailable, 1: workflow fails, 2: success
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		switch phase.Load() {
		case 0:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 1:
			_, _ = io.WriteString(w, `{"status":"Failed"}`)
		default:
			_, _ = io.WriteString(w, successReply)
		}
	}))
	t.Cleanup(srv.Close)
	spool := filepath.Join(t.TempDir(), "spool")
	env := testEnvelope()
	opts := Options{
		Endpoint: srv.URL, ChunkBytes: 0, MaxRetries: 1, SpoolDir: spool,
		ScanID: env.ScanID, Sleep: noSleep, Jitter: noJitter,
	}

	res, err := Send(env, opts)
	if err != nil || res.Delivered || res.Spooled != 1 {
		t.Fatalf("expected one spooled chunk while unavailable: %+v, %v", res, err)
	}

	phase.Store(1)
	res, err = Send(env, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Delivered || res.Spooled != 0 || len(res.Unconfirmed) != 2 {
		t.Fatalf("replay and new chunk should both be unconfirmed and nothing kept: %+v", res)
	}
	if !strings.HasPrefix(res.Unconfirmed[0], "spooled ") {
		t.Fatalf("first unconfirmed entry should be the spooled replay: %q", res.Unconfirmed)
	}

	phase.Store(2)
	posts.Store(0)
	res, err = Send(env, opts)
	if err != nil || !res.Delivered || res.Spooled != 0 || len(res.Unconfirmed) != 0 {
		t.Fatalf("expected clean delivery: %+v, %v", res, err)
	}
	if posts.Load() != int32(res.Chunks) {
		t.Fatalf("dropped spool was replayed: posts=%d chunks=%d", posts.Load(), res.Chunks)
	}
}

func TestScopeIsExactAndNamesTheSpool(t *testing.T) {
	const ep = "https://example.invalid/ingest"
	a := Scope(ep, "synthetic-key-a")
	if filepath.Base(scopedSpoolDir(t.TempDir(), ep, "synthetic-key-a")) != a {
		t.Fatal("spool directory is not named by Scope")
	}
	others := map[string][2]string{
		"trailing slash":   {ep + "/", "synthetic-key-a"},
		"leading space":    {" " + ep, "synthetic-key-a"},
		"other key":        {ep, "synthetic-key-b"},
		"no key":           {ep, ""},
		"shifted boundary": {ep + "s", "ynthetic-key-a"},
	}
	for name, o := range others {
		if Scope(o[0], o[1]) == a {
			t.Fatalf("%s shares a scope", name)
		}
	}
}
