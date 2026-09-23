package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// maxEnrollResponseBytes bounds the enrollment response we will read.
const maxEnrollResponseBytes = 64 << 10

// EnrollResponse is the frozen POST /api/devices/enroll success shape
// (docs/architecture/device-control-plane/enrollment.schema.json).
type EnrollResponse struct {
	DeviceID  string `json:"device_id"`
	DeviceKey string `json:"device_key"`
	Status    string `json:"status"`
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// ValidateBifrostURL requires an absolute URL with a host. Credential-bearing
// serve traffic (enrollment token, device key) must use https; plain http is
// accepted only for loopback hosts (local development and test servers).
func ValidateBifrostURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("missing Bifrost URL (-bifrost-url / SOPDET_BIFROST_URL)")
	}
	u, err := url.ParseRequestURI(strings.TrimRight(raw, "/"))
	if err != nil {
		return fmt.Errorf("invalid Bifrost URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid Bifrost URL scheme %q (want http or https)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid Bifrost URL: missing host")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf(
			"refusing credential-bearing URL over plain http (use https; http is allowed only on loopback, got %q)",
			u.Hostname(),
		)
	}
	return nil
}

func isLoopbackHost(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// enrollHTTPClient returns a client that refuses redirects so the one-time
// enrollment POST body (and any future credential-bearing request) is never
// re-sent to another scheme or host. The input client is shallow-copied;
// its transport is reused.
func enrollHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	clone := *client
	prev := clone.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if prev != nil {
			if err := prev(req, via); err != nil {
				return err
			}
		}
		return fmt.Errorf("refusing redirect during enrollment (credential-bearing request must not follow redirects)")
	}
	return &clone
}

// Enroll exchanges a single-use enrollment token for the device key.
// The token and key are secrets: they never appear in returned errors.
func Enroll(
	ctx context.Context,
	baseURL string,
	enrollmentToken string,
	client *http.Client,
) (DeviceState, error) {
	if err := ValidateBifrostURL(baseURL); err != nil {
		return DeviceState{}, err
	}
	if enrollmentToken == "" {
		return DeviceState{}, fmt.Errorf("missing enrollment token")
	}
	client = enrollHTTPClient(client)

	body, err := json.Marshal(map[string]string{
		"enrollment_token": enrollmentToken,
	})
	if err != nil {
		return DeviceState{}, err
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/api/devices/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return DeviceState{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return DeviceState{}, fmt.Errorf("enroll request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollResponseBytes))
	if err != nil {
		return DeviceState{}, fmt.Errorf("enroll response read failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return DeviceState{}, enrollError(resp.StatusCode, raw)
	}

	var parsed EnrollResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return DeviceState{}, fmt.Errorf("enroll response is not valid JSON")
	}
	if parsed.DeviceID == "" {
		return DeviceState{}, fmt.Errorf("enroll response missing device_id")
	}
	if _, err := uuid.Parse(parsed.DeviceID); err != nil {
		return DeviceState{}, fmt.Errorf("enroll response device_id is not a UUID")
	}
	if !ValidDeviceKeyFormat(parsed.DeviceKey) {
		return DeviceState{}, fmt.Errorf("enroll response device_key has unexpected format")
	}
	keyID, ok := ParseDeviceKeyID(parsed.DeviceKey)
	if !ok || keyID != parsed.DeviceID {
		return DeviceState{}, fmt.Errorf("enroll response device_key does not match device_id")
	}
	if parsed.Status != "" && parsed.Status != "active" {
		return DeviceState{}, fmt.Errorf("enroll landed in unexpected status %q", parsed.Status)
	}

	return DeviceState{
		BifrostURL: strings.TrimRight(baseURL, "/"),
		DeviceID:   parsed.DeviceID,
		DeviceKey:  parsed.DeviceKey,
	}, nil
}

// enrollError renders a non-200 enroll response using only the structured
// error envelope (code/message), so raw bodies that might echo a token are
// never propagated.
func enrollError(status int, raw []byte) error {
	var env errorEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && env.Error.Code != "" {
		return fmt.Errorf("enroll rejected: HTTP %d code=%s", status, env.Error.Code)
	}
	return fmt.Errorf("enroll rejected: HTTP %d", status)
}
