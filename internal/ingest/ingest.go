// Package ingest delivers inventory envelopes to a Bifrost endpoint with
// gzip compression, entity-boundary chunking, retry/backoff, and a durable spool.
package ingest

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// Unconfirmed lists chunks the endpoint answered without confirming a
	// successful workflow run (for example status "Failed", "Timeout" or an
	// async "Pending"). They are neither retried nor spooled: the workflow
	// may already have run. The caller must not advance its delta baseline,
	// so the next scan resends the changes.
	Unconfirmed []string
}

// successStatus is the only Bifrost endpoint workflow status that confirms
// the chunk was applied. Upstream answers HTTP 200 for every sync outcome,
// including "Failed" and "Timeout", and "Pending" for async workflows.
const successStatus = "Success"

// maxResponseBytes bounds how much of an endpoint response is read.
const maxResponseBytes = 1 << 20

type postOutcome int

const (
	// postDelivered: HTTP 2xx and the workflow reported Success.
	postDelivered postOutcome = iota
	// postRetry: transport error or non-2xx; retry, then spool.
	postRetry
	// postUnconfirmed: the endpoint answered without confirming success.
	// Never resend; the next scan recomputes from the confirmed baseline.
	postUnconfirmed
)

// endpointResponse is the subset of Bifrost's EndpointExecuteResponse used
// to confirm delivery. The workflow's error text is deliberately not read.
type endpointResponse struct {
	ExecutionID string `json:"execution_id"`
	Status      string `json:"status"`
}

// confirmDelivery classifies a 2xx endpoint response body.
func confirmDelivery(raw []byte) (bool, string) {
	var r endpointResponse
	if err := json.Unmarshal(raw, &r); err != nil || r.Status == "" {
		return false, "response did not report a workflow status"
	}
	if r.Status == successStatus {
		return true, ""
	}
	reason := fmt.Sprintf("workflow status %q", sanitizeField(r.Status))
	if r.ExecutionID != "" {
		reason += fmt.Sprintf(" (execution %s)", sanitizeField(r.ExecutionID))
	}
	return false, reason
}

// sanitizeField keeps server-supplied identifiers short and printable.
func sanitizeField(v string) string {
	var b strings.Builder
	for _, r := range v {
		if b.Len() >= 64 {
			break
		}
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
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
		clone := *o.HTTPClient
		clone.CheckRedirect = rejectIngestRedirect
		return &clone, nil
	}
	tr := &http.Transport{}
	if o.Proxy != "" {
		pu, err := url.Parse(o.Proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Timeout: 90 * time.Second, Transport: tr, CheckRedirect: rejectIngestRedirect}, nil
}

func rejectIngestRedirect(_ *http.Request, _ []*http.Request) error {
	return fmt.Errorf("refusing ingest redirect")
}

func validateEndpoint(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("invalid ingest endpoint")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme == "http" && (strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("ingest endpoint must use https (http is allowed only on loopback)")
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

// Scope names the identity pending inventory is bound to: this implementation,
// the endpoint exactly as configured, and the credential. It names the spool
// directory, and the delta baseline records it so a baseline and the chunks
// still spooled for it always share one identity.
func Scope(endpoint, apiKey string) string {
	sum := sha256.Sum256([]byte("go\x00" + endpoint + "\x00" + apiKey))
	return fmt.Sprintf("go-%x", sum[:16])
}

// scopedSpoolDir binds pending inventory to its original implementation,
// endpoint and credential. Legacy unscoped files are never replayed.
func scopedSpoolDir(base, endpoint, apiKey string) string {
	if base == "" {
		return ""
	}
	return filepath.Join(base, Scope(endpoint, apiKey))
}

// Send delivers an envelope, draining any previously spooled chunks first.
func Send(env *schema.Envelope, opts Options) (Result, error) {
	res := Result{}
	if err := validateEndpoint(opts.Endpoint); err != nil {
		return res, err
	}
	opts.SpoolDir = scopedSpoolDir(opts.SpoolDir, opts.Endpoint, opts.APIKey)
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

	drained, unconfirmed := opts.drain(client)
	res.Unconfirmed = append(res.Unconfirmed, unconfirmed...)
	if !drained {
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
		switch outcome, reason := opts.post(client, req); outcome {
		case postDelivered:
		case postUnconfirmed:
			res.Unconfirmed = append(res.Unconfirmed, fmt.Sprintf("chunk %d: %s", i, reason))
			failed = true
		default:
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

// drain replays spooled chunks. A replay the endpoint answers without
// confirming success is removed rather than replayed again: its scan never
// advanced the delta baseline, so later scans resend those changes.
func (o *Options) drain(client *http.Client) (bool, []string) {
	if o.SpoolDir == "" {
		return true, nil
	}
	entries, err := os.ReadDir(o.SpoolDir)
	if err != nil {
		return true, nil
	}
	ok := true
	var unconfirmed []string
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
		switch outcome, reason := o.post(client, data); outcome {
		case postDelivered:
			_ = os.Remove(p)
		case postUnconfirmed:
			_ = os.Remove(p)
			unconfirmed = append(unconfirmed, fmt.Sprintf("spooled %s: %s", e.Name(), reason))
			ok = false
		default:
			ok = false
		}
	}
	return ok, unconfirmed
}

// post sends one chunk. Transport errors and non-2xx statuses are retried;
// a 2xx answer is final either way, because the workflow may have run.
func (o *Options) post(client *http.Client, payload []byte) (postOutcome, string) {
	attempts := o.MaxRetries
	if attempts < 1 {
		attempts = 1
	}
	for a := 0; a < attempts; a++ {
		req, err := http.NewRequest(http.MethodPost, o.Endpoint, bytes.NewReader(payload))
		if err != nil {
			return postRetry, ""
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Accept", "application/json")
		if o.APIKey != "" {
			req.Header.Set("X-Bifrost-Key", o.APIKey)
		}
		resp, err := client.Do(req)
		if err == nil {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if readErr != nil {
					return postUnconfirmed, "response could not be read"
				}
				if ok, reason := confirmDelivery(raw); !ok {
					return postUnconfirmed, reason
				}
				return postDelivered, ""
			}
		}
		if a < attempts-1 {
			backoff := time.Duration(1<<uint(a)) * 500 * time.Millisecond
			o.sleep(backoff + o.jitter(500*time.Millisecond))
		}
	}
	return postRetry, ""
}

func (o *Options) spool(index int, payload []byte) error {
	if o.SpoolDir == "" {
		return nil
	}
	if err := os.MkdirAll(o.SpoolDir, 0o700); err != nil {
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
