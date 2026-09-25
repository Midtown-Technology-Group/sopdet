package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// EndpointError is a structured device-control-plane error envelope
// (docs/architecture/device-control-plane/error.schema.json).
type EndpointError struct {
	Status    int    `json:"-"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	JobID     string `json:"job_id,omitempty"`
}

func (e *EndpointError) Error() string {
	return fmt.Sprintf("bifrost %d (%s): %s", e.Status, e.Code, e.Message)
}

// ErrFenced is returned when the server rejects our claim_token
// (fence_violation / job_terminal). The caller must NEVER re-run locally —
// the server owns the outcome (M0: terminal lost, explicit new job only).
var ErrFenced = errors.New("claim fenced by server (do not re-run locally)")

const (
	defaultMaxRetries = 4
	defaultBaseDelay  = 500 * time.Millisecond
	maxResponseBytes  = 512 << 10 // largest legal claim response: 256 KiB script + 32 KiB params + envelope/margin
	// spoolFileTTL mirrors the M0 retention freeze: unsent spool files are
	// swept 7 days after mtime (they are useless once the server has long
	// passed terminal on their job).
	spoolFileTTL = 7 * 24 * time.Hour
)

// ClaimedJob mirrors the frozen claim-response schema.
type ClaimedJob struct {
	JobID             string         `json:"job_id"`
	ScriptName        string         `json:"script_name"`
	ScriptContent     string         `json:"script_content"`
	Params            map[string]any `json:"params"`
	TimeoutSeconds    int            `json:"timeout_seconds"`
	MaxOutputBytes    int64          `json:"max_output_bytes"`
	ClaimToken        string         `json:"claim_token"`
	ClaimedAt         time.Time      `json:"claimed_at"`
	ClaimLeaseSeconds int            `json:"claim_lease_seconds"`
}

// HeartbeatStatus is the frozen heartbeat response.
type HeartbeatStatus struct {
	ServerTime          time.Time  `json:"server_time"`
	LastSeenAt          *time.Time `json:"last_seen_at"`
	PollIntervalSeconds int        `json:"poll_interval_seconds"`
	CancelRequested     bool       `json:"cancel_requested"`
}

// LogBatchEntry matches the frozen log-batch schema (seq is assigned by the
// claiming agent, monotonic per job starting at 1).
type LogBatchEntry struct {
	Seq    int       `json:"seq"`
	Stream string    `json:"stream"`
	Text   string    `json:"text"`
	TS     time.Time `json:"ts"`
}

// ResultPayload matches the frozen result schema.
type ResultPayload struct {
	ClaimToken string `json:"claim_token"`
	Status     string `json:"status"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Error      string `json:"error,omitempty"`
	Output     string `json:"output,omitempty"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
}

// Client talks to the Bifrost device protocol over HTTP. It has no
// knowledge of PowerShell: the serve loop wires the Runner into it (M3.5).
type Client struct {
	BaseURL   string
	DeviceKey string
	SpoolDir  string
	SessionID string
	// AgentVersion is the build version reported on every heartbeat as
	// `agent_version` (the device row column, String(64)). It is sanitized
	// (control characters stripped, truncated to 64) at send time; an empty
	// value omits the field entirely rather than posting "".
	AgentVersion string
	MaxRetries   int
	HTTP         *http.Client
	Sleep        func(time.Duration)
	Jitter       func(time.Duration) time.Duration
}

// NewClient builds a client with per-process agent session identity.
func NewClient(baseURL, deviceKey, spoolDir string) *Client {
	return &Client{
		BaseURL:    trimBase(baseURL),
		DeviceKey:  deviceKey,
		SpoolDir:   spoolDir,
		SessionID:  uuid.NewString(),
		MaxRetries: defaultMaxRetries,
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		// Sleep stays nil in production: waitBackoff then honours context
		// cancellation between retries. Tests inject a zero Sleep.
		Jitter: func(d time.Duration) time.Duration {
			if d <= 0 {
				return 0
			}
			return time.Duration(rand.Int63n(int64(d)))
		},
	}
}

func trimBase(base string) string {
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	return base
}

// waitBackoff sleeps between retries while honouring context cancellation
// (so a shutdown does not sit through the full exponential backoff). The
// injectable Sleep path is for tests and short-circuits ctx, matching the
// ingest package's pattern.
func (c *Client) waitBackoff(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		c.Sleep(d)
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) jitter(d time.Duration) time.Duration {
	if c.Jitter != nil {
		return c.Jitter(d)
	}
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(d)))
}

// post sends one JSON request with retry/backoff on network errors and 5xx.
// 4xx responses are returned immediately as *EndpointError (never retried);
// fence/terminal rejections map to ErrFenced so callers can accept the
// server's verdict without any local re-run.
func (c *Client) post(
	ctx context.Context,
	path string,
	payload any,
	out any,
) error {
	retries := c.MaxRetries
	if retries <= 0 {
		retries = defaultMaxRetries
	}
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * defaultBaseDelay
			if err := c.waitBackoff(ctx, backoff+c.jitter(500*time.Millisecond)); err != nil {
				return err // context cancelled during backoff
			}
		}
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(
			ctx, http.MethodPost, c.BaseURL+path, reader,
		)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Bifrost-Key", c.DeviceKey)

		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if len(raw) > maxResponseBytes {
			// Explicit truncation detection: a silently-cut claim body would
			// fail decode AFTER the server already claimed the job (it would
			// then go `lost`). Fail loudly instead; the lease expiry makes
			// the job safely reclaimable pre-spawn.
			return fmt.Errorf(
				"response truncated: body exceeds %d bytes", maxResponseBytes,
			)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(raw) > 0 {
				if err := json.Unmarshal(raw, out); err != nil {
					return fmt.Errorf("decode response: %w", err)
				}
			}
			return nil
		}

		epErr := decodeEndpointError(resp.StatusCode, raw)
		if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500 {
			// Transient server-side: retry then surface.
			lastErr = epErr
			continue
		}
		return epErr // 4xx: never retry (busy/fence/scope are terminal here)
	}
	return lastErr
}

func decodeEndpointError(status int, raw []byte) *EndpointError {
	var env struct {
		Error EndpointError `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && env.Error.Code != "" {
		env.Error.Status = status
		return &env.Error
	}
	return &EndpointError{
		Status:  status,
		Code:    "http_error",
		Message: fmt.Sprintf("unexpected HTTP %d", status),
	}
}

// IsFenced reports whether err means the server rejected our claim (fence
// violation or terminal job). Callers must accept it — never re-run.
func IsFenced(err error) bool {
	var epErr *EndpointError
	if errors.As(err, &epErr) {
		return epErr.Code == "fence_violation" || epErr.Code == "job_terminal"
	}
	return false
}

func fencedOr(err error) error {
	if IsFenced(err) {
		return fmt.Errorf("%w: %w", ErrFenced, err)
	}
	return err
}

// Heartbeat posts the session heartbeat (plus the sanitized build version so
// the device row's agent_version can be verified by the runbook) and returns
// the poll hint plus the cooperative-cancel flag for the job this session
// owns (may be none).
func (c *Client) Heartbeat(ctx context.Context) (*HeartbeatStatus, error) {
	payload := map[string]string{
		"agent_session_id": c.SessionID,
	}
	// A zero version omits the key instead of sending "": the runbook check
	// is "agent_version set", and an empty string would satisfy it while
	// telling an operator nothing.
	if v := sanitizeAgentVersion(c.AgentVersion); v != "" {
		payload["agent_version"] = v
	}
	var out HeartbeatStatus
	err := c.post(ctx, "/api/device/heartbeat", payload, &out)
	if err != nil {
		return nil, fencedOr(err)
	}
	return &out, nil
}

// agentVersionColumnWidth matches the platform's agent_version column
// (String(64)). Truncation is by rune so a multi-byte version string stays
// valid UTF-8 after the cut.
const agentVersionColumnWidth = 64

// sanitizeAgentVersion strips control characters (they must never reach a
// database column or a log line) and truncates to the agent_version column
// width. The empty string passes through unchanged.
func sanitizeAgentVersion(v string) string {
	if v == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	runes := []rune(b.String())
	if len(runes) > agentVersionColumnWidth {
		runes = runes[:agentVersionColumnWidth]
	}
	return string(runes)
}

// Claim fetches the next job. Returns (nil, nil) when the server has no
// work (HTTP 204).
func (c *Client) Claim(ctx context.Context) (*ClaimedJob, error) {
	var out ClaimedJob
	err := c.post(ctx, "/api/device/jobs/claim", map[string]string{
		"agent_session_id": c.SessionID,
	}, &out)
	if err != nil {
		return nil, fencedOr(err)
	}
	if out.JobID == "" {
		return nil, nil // 204 idle
	}
	return &out, nil
}

// ReportRunning reports a REAL spawn (claimed -> running). Callers must
// invoke it only after the process actually started (feedback #1).
func (c *Client) ReportRunning(ctx context.Context, jobID, claimToken string) error {
	err := c.post(ctx, "/api/device/jobs/"+jobID+"/running", map[string]string{
		"claim_token":      claimToken,
		"agent_session_id": c.SessionID,
	}, nil)
	return fencedOr(err)
}

// PostLogs sends a fenced, idempotent log batch. On transient failure the
// batch is spooled to disk (0600) for a later drain.
func (c *Client) PostLogs(
	ctx context.Context,
	jobID, claimToken string,
	entries []LogBatchEntry,
) error {
	payload := map[string]any{
		"claim_token": claimToken,
		"entries":     entries,
	}
	err := c.post(ctx, "/api/device/jobs/"+jobID+"/logs", payload, nil)
	if err == nil {
		return nil
	}
	var epErr *EndpointError
	if errors.As(err, &epErr) && !epErr.Retryable && epErr.Status < 500 {
		// Server rejected permanently (fence/terminal/bounds): accept.
		return fencedOr(err)
	}
	// Transient: keep the logs durably; drain on a later call.
	if spoolErr := c.Spool(&SpoolRecord{
		Kind:       "logs",
		JobID:      jobID,
		ClaimToken: claimToken,
		Payload:    payload,
	}); spoolErr != nil {
		return fmt.Errorf("post logs: %v (spool: %w)", err, spoolErr)
	}
	return nil
}

// ReportResult posts the terminal result. On transient failure it spools
// the result (0600) for drain; a fenced rejection is surfaced as ErrFenced
// AND the spooled copy (if any) is dropped — the server's verdict wins.
func (c *Client) ReportResult(
	ctx context.Context,
	jobID string,
	result ResultPayload,
) error {
	// Drain first: any logs spooled during an outage must reach the server
	// BEFORE the terminal result, or observation would silently lose them.
	if c.SpoolDir != "" {
		_, _ = c.DrainSpool(ctx) // best-effort; the result matters more
	}
	err := c.post(ctx, "/api/device/jobs/"+jobID+"/result", result, nil)
	if err == nil {
		return nil
	}
	if IsFenced(err) {
		// Server already terminal (e.g. wrote `lost`): accept, never re-run.
		_ = c.dropSpooledForJob(jobID)
		return fmt.Errorf("%w: %w", ErrFenced, err)
	}
	var epErr *EndpointError
	if errors.As(err, &epErr) && !epErr.Retryable && epErr.Status < 500 {
		return err
	}
	if spoolErr := c.Spool(&SpoolRecord{
		Kind:       "result",
		JobID:      jobID,
		ClaimToken: result.ClaimToken,
		Payload:    result,
	}); spoolErr != nil {
		return fmt.Errorf("post result: %v (spool: %w)", err, spoolErr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Durable spool: 0600 files, drained on reconnect, fenced drops accepted.
// ---------------------------------------------------------------------------

// SpoolRecord is one unsent protocol payload persisted for retry.
type SpoolRecord struct {
	Kind       string    `json:"kind"` // "logs" | "result"
	JobID      string    `json:"job_id"`
	ClaimToken string    `json:"claim_token"`
	Payload    any       `json:"payload"`
	CreatedAt  time.Time `json:"created_at"`
}

// Spool persists a record with mode 0600 (the M5 installer applies the
// SYSTEM/Administrators DACL on Windows; chmod is best-effort there).
func (c *Client) Spool(rec *SpoolRecord) error {
	if c.SpoolDir == "" {
		return nil
	}
	if err := os.MkdirAll(c.SpoolDir, 0o700); err != nil {
		return err
	}
	rec.CreatedAt = time.Now().UTC()
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s-%d.json", rec.Kind, rec.JobID, time.Now().UnixNano())
	path := filepath.Join(c.SpoolDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

func (c *Client) dropSpooledForJob(jobID string) error {
	if c.SpoolDir == "" {
		return nil
	}
	entries, err := os.ReadDir(c.SpoolDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		rec, err := c.readSpoolRecord(filepath.Join(c.SpoolDir, e.Name()))
		if err != nil {
			continue
		}
		if rec.JobID == jobID {
			os.Remove(filepath.Join(c.SpoolDir, e.Name()))
		}
	}
	return nil
}

func (c *Client) readSpoolRecord(path string) (*SpoolRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec SpoolRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// DrainSpool replays unsent records in creation order. Successfully posted
// records are removed; fenced rejections are accepted (record dropped —
// never a local re-run); transient failures stop the drain so the record
// can retry later. Returns the number of records still pending.
func (c *Client) DrainSpool(ctx context.Context) (int, error) {
	if c.SpoolDir == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(c.SpoolDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var paths []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			paths = append(paths, filepath.Join(c.SpoolDir, e.Name()))
		}
	}
	sort.Strings(paths) // creation-order approximation (nano timestamps in name)

	pending := 0
	for i, path := range paths {
		rec, err := c.readSpoolRecord(path)
		if err != nil {
			// Corrupt record: quarantine is overkill; drop it (it contains
			// protocol payloads that were never acknowledged anyway).
			os.Remove(path)
			continue
		}
		var postErr error
		switch rec.Kind {
		case "logs":
			payload, ok := rec.Payload.(map[string]any)
			if !ok {
				os.Remove(path)
				continue
			}
			postErr = c.post(ctx, "/api/device/jobs/"+rec.JobID+"/logs", payload, nil)
		case "result":
			payload, ok := rec.Payload.(map[string]any)
			if !ok {
				os.Remove(path)
				continue
			}
			postErr = c.post(ctx, "/api/device/jobs/"+rec.JobID+"/result", payload, nil)
		default:
			os.Remove(path)
			continue
		}
		if postErr == nil {
			os.Remove(path)
			continue
		}
		if IsFenced(postErr) {
			// Server already owns the outcome: accept, drop, never re-run.
			os.Remove(path)
			continue
		}
		var epErr *EndpointError
		if errors.As(postErr, &epErr) && !epErr.Retryable && epErr.Status < 500 {
			os.Remove(path)
			continue
		}
		// Transient: keep for the next drain; count EVERY retained record,
		// not just the one we stopped on.
		pending = len(paths) - i
		break
	}
	return pending, nil
}

// SweepSpool removes spool files older than the M0 7-day retention
// window. Call it once at serve startup.
func (c *Client) SweepSpool() (int, error) {
	if c.SpoolDir == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(c.SpoolDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	cutoff := time.Now().Add(-spoolFileTTL)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if os.Remove(filepath.Join(c.SpoolDir, e.Name())) == nil {
				removed++
			}
		}
	}
	return removed, nil
}
