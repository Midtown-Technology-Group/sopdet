package ingest

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

var noSleep = func(time.Duration) {}
var noJitter = func(time.Duration) time.Duration { return 0 }

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

func recorder(t *testing.T, failFirst int, status int) (*httptest.Server, *[]received, *int) {
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

func TestSpoolThenDrain(t *testing.T) {
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
		t.Fatalf("expected drain + deliver, got %+v (received %d)", res2, len(*got))
	}
}
