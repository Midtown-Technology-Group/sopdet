// Package ingest delivers inventory envelopes to a Bifrost endpoint with
// gzip compression, entity-boundary chunking, retry/backoff, and a durable spool.
package ingest

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// Options controls delivery.
type Options struct {
	Endpoint   string
	APIKey     string
	Compress   bool
	ChunkBytes int
	MaxRetries int
	Proxy      string
	SpoolDir   string
	ScanID     string

	HTTPClient *http.Client
	Sleep      func(time.Duration)
	Jitter     func(time.Duration) time.Duration
}

// Result summarises a delivery attempt.
type Result struct {
	Delivered         bool
	Chunks            int
	Spooled           int
	UncompressedBytes int
	CompressedBytes   int
}

type body struct {
	Payload         string  `json:"payload"`
	ContentEncoding *string `json:"content_encoding"`
	ScanID          string  `json:"scan_id"`
	ChunkIndex      int     `json:"chunk_index"`
	ChunkCount      int     `json:"chunk_count"`
}

func (o *Options) sleep(d time.Duration) {
	if o.Sleep != nil {
		o.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (o *Options) jitter(d time.Duration) time.Duration {
	if o.Jitter != nil {
		return o.Jitter(d)
	}
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(d)))
}

func (o *Options) client() (*http.Client, error) {
	if o.HTTPClient != nil {
		return o.HTTPClient, nil
	}
	tr := &http.Transport{}
	if o.Proxy != "" {
		pu, err := url.Parse(o.Proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Timeout: 90 * time.Second, Transport: tr}, nil
}

func gzipBase64(s string) (string, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(zw, s); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func wire(payload string, compress bool) (string, error) {
	if compress {
		return gzipBase64(payload)
	}
	return payload, nil
}

// Send delivers an envelope, draining any previously spooled chunks first.
func Send(env *schema.Envelope, opts Options) (Result, error) {
	res := Result{}
	full, err := json.Marshal(env)
	if err != nil {
		return res, err
	}
	res.UncompressedBytes = len(full)

	all, err := wire(string(full), opts.Compress)
	if err != nil {
		return res, err
	}
	res.CompressedBytes = len(all)

	names := make([]string, 0, len(env.Entities))
	for n := range env.Entities {
		names = append(names, n)
	}
	sort.Strings(names)

	var groups []map[string]any
	if opts.ChunkBytes <= 0 || len(all) <= opts.ChunkBytes {
		groups = append(groups, env.Entities)
	} else {
		cur := map[string]any{}
		for _, n := range names {
			trial := map[string]any{}
			for k, v := range cur {
				trial[k] = v
			}
			trial[n] = env.Entities[n]
			candidate := env.CloneWithEntities(trial, nil)
			cj, _ := json.Marshal(candidate)
			w, _ := wire(string(cj), opts.Compress)
			if len(w) > opts.ChunkBytes && len(cur) > 0 {
				groups = append(groups, cur)
				cur = map[string]any{n: env.Entities[n]}
				continue
			}
			cur[n] = env.Entities[n]
		}
		if len(cur) > 0 {
			groups = append(groups, cur)
		}
	}

	res.Chunks = len(groups)
	client, err := opts.client()
	if err != nil {
		return res, err
	}
	failed := false

	if !opts.drain(client) {
		failed = true
	}

	for i, g := range groups {
		keys := make([]string, 0, len(g))
		for k := range g {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		chunkEnv := env.CloneWithEntities(g, &schema.Chunk{Index: i, Count: len(groups), Entities: keys})
		cj, err := json.Marshal(chunkEnv)
		if err != nil {
			return res, err
		}
		payload, err := wire(string(cj), opts.Compress)
		if err != nil {
			return res, err
		}
		req, err := json.Marshal(body{Payload: payload, ScanID: opts.ScanID, ChunkIndex: i, ChunkCount: len(groups)})
		if opts.Compress {
			enc := "gzip+base64"
			req, err = json.Marshal(body{Payload: payload, ContentEncoding: &enc, ScanID: opts.ScanID, ChunkIndex: i, ChunkCount: len(groups)})
		}
		if err != nil {
			return res, err
		}
		if !opts.post(client, req) {
			if err := opts.spool(i, req); err != nil {
				return res, err
			}
			failed = true
		}
	}
	res.Delivered = !failed
	if p, err := opts.pending(); err == nil {
		res.Spooled = p
	}
	return res, nil
}

func (o *Options) drain(client *http.Client) bool {
	if o.SpoolDir == "" {
		return true
	}
	entries, err := os.ReadDir(o.SpoolDir)
	if err != nil {
		return true
	}
	ok := true
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		p := filepath.Join(o.SpoolDir, e.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			ok = false
			continue
		}
		if o.post(client, data) {
			_ = os.Remove(p)
		} else {
			ok = false
		}
	}
	return ok
}

func (o *Options) post(client *http.Client, payload []byte) bool {
	attempts := o.MaxRetries
	if attempts < 1 {
		attempts = 1
	}
	for a := 0; a < attempts; a++ {
		req, err := http.NewRequest(http.MethodPost, o.Endpoint, bytes.NewReader(payload))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		if o.APIKey != "" {
			req.Header.Set("X-Bifrost-Key", o.APIKey)
		}
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return true
			}
		}
		if a < attempts-1 {
			backoff := time.Duration(1<<uint(a)) * 500 * time.Millisecond
			o.sleep(backoff + o.jitter(500*time.Millisecond))
		}
	}
	return false
}

func (o *Options) spool(index int, payload []byte) error {
	if o.SpoolDir == "" {
		return nil
	}
	if err := os.MkdirAll(o.SpoolDir, 0o755); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%d.json", o.ScanID, index)
	return os.WriteFile(filepath.Join(o.SpoolDir, name), payload, 0o600)
}

func (o *Options) pending() (int, error) {
	if o.SpoolDir == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(o.SpoolDir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			n++
		}
	}
	return n, nil
}
