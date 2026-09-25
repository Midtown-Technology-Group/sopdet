package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const testSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 chars

func testDeviceKey() string {
	return deviceKeyPrefix + uuid.NewString() + "_" + testSecret
}

func testStatePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "serve.json")
}

func newEnrollServer(t *testing.T, token string, status int, payload string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/devices/enroll" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("request body not JSON: %v", err)
		}
		if req["enrollment_token"] != token {
			t.Errorf("enrollment_token mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnrollSuccess(t *testing.T) {
	token := enrollmentTokenPrefix + uuid.NewString() + "_" + testSecret
	deviceID := uuid.NewString()
	key := deviceKeyPrefix + deviceID + "_" + testSecret
	payload, _ := json.Marshal(map[string]string{
		"device_id":  deviceID,
		"device_key": key,
		"status":     "active",
	})
	srv := newEnrollServer(t, token, http.StatusOK, string(payload))

	state, err := Enroll(context.Background(), srv.URL, token, srv.Client())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if state.DeviceID != deviceID {
		t.Errorf("device id = %s, want %s", state.DeviceID, deviceID)
	}
	if state.DeviceKey != key {
		t.Errorf("device key not returned")
	}
	if state.BifrostURL != srv.URL {
		t.Errorf("base url = %q, want %q", state.BifrostURL, srv.URL)
	}
	if !strings.HasPrefix(state.DeviceKey, deviceKeyPrefix) {
		t.Errorf("device key prefix missing")
	}
}

func TestEnrollErrorEnvelopeDoesNotLeakToken(t *testing.T) {
	token := enrollmentTokenPrefix + uuid.NewString() + "_" + testSecret
	payload := `{"error":{"code":"enrollment_token_expired","message":"token expired"}}`
	srv := newEnrollServer(t, token, http.StatusUnauthorized, payload)

	_, err := Enroll(context.Background(), srv.URL, token, srv.Client())
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "enrollment_token_expired") {
		t.Errorf("error should surface the machine code, got: %s", msg)
	}
	if strings.Contains(msg, token) {
		t.Errorf("error leaked the enrollment token")
	}
	if strings.Contains(msg, "token expired") {
		t.Errorf("error should not echo server message body, got: %s", msg)
	}
}

func TestEnrollNonJSONErrorDoesNotLeakBody(t *testing.T) {
	token := enrollmentTokenPrefix + uuid.NewString() + "_" + testSecret
	srv := newEnrollServer(t, token, http.StatusBadGateway, "upstream exploded "+token)

	_, err := Enroll(context.Background(), srv.URL, token, srv.Client())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaked the enrollment token: %v", err)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should include status, got: %v", err)
	}
}

func TestEnrollRejectsBadResponses(t *testing.T) {
	token := enrollmentTokenPrefix + uuid.NewString() + "_" + testSecret
	mismatchedKey := deviceKeyPrefix + uuid.NewString() + "_" + testSecret
	cases := []string{
		`{"device_id":"","device_key":"","status":""}`,
		`{"device_id":"` + uuid.NewString() + `","device_key":"nope","status":"active"}`,
		`{"device_id":"` + uuid.NewString() + `","device_key":"bfdk_` + uuid.NewString() + `_short","status":"active"}`,
		`{"device_id":"` + uuid.NewString() + `","device_key":"` + mismatchedKey + `","status":"active"}`,
		`{"device_id":"` + uuid.NewString() + `","device_key":"` + deviceKeyPrefix + uuid.NewString() + `_` + testSecret + `","status":"disabled"}`,
		`not-json`,
	}
	for i, payload := range cases {
		srv := newEnrollServer(t, token, http.StatusOK, payload)
		_, err := Enroll(context.Background(), srv.URL, token, srv.Client())
		if err == nil {
			t.Errorf("case %d: expected error", i)
		}
		if err != nil && strings.Contains(err.Error(), token) {
			t.Errorf("case %d: leaked token: %v", i, err)
		}
	}
}

func TestEnrollRefusesRedirects(t *testing.T) {
	token := enrollmentTokenPrefix + uuid.NewString() + "_" + testSecret
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	_, err := Enroll(context.Background(), srv.URL, token, srv.Client())
	if err == nil {
		t.Fatal("expected redirect refusal")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error should mention redirect refusal, got: %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaked token: %v", err)
	}
	if hits != 1 {
		t.Errorf("redirect must not be followed; hits = %d", hits)
	}
}

func TestDeviceStateRoundTripAndMode(t *testing.T) {
	path := testStatePath(t)
	state := DeviceState{
		BifrostURL: "https://bifrost.example",
		DeviceID:   uuid.NewString(),
		DeviceKey:  testDeviceKey(),
	}
	if err := SaveDeviceState(path, state); err != nil {
		t.Fatalf("SaveDeviceState: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("state file mode = %o, want 600", perm)
		}
	}
	got, err := LoadDeviceState(path)
	if err != nil {
		t.Fatalf("LoadDeviceState: %v", err)
	}
	if got != state {
		t.Errorf("round trip mismatch: %+v != %+v", got, state)
	}
}

func TestLoadDeviceStateMissingFileIsZero(t *testing.T) {
	got, err := LoadDeviceState(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.DeviceKey != "" {
		t.Errorf("expected zero state")
	}
}

func TestSaveDeviceStateRefusesEmptyKey(t *testing.T) {
	err := SaveDeviceState(testStatePath(t), DeviceState{BifrostURL: "https://x"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPrepareServeRefusesWithoutURL(t *testing.T) {
	_, err := PrepareServe(context.Background(), ServeConfig{StatePath: testStatePath(t)}, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing to serve") {
		t.Fatalf("expected refuse error, got: %v", err)
	}
}

func TestPrepareServeAdoptsExplicitKeyAndPersists(t *testing.T) {
	path := testStatePath(t)
	key := testDeviceKey()
	deviceID, _ := ParseDeviceKeyID(key)
	cfg := ServeConfig{
		BifrostURL: "https://bifrost.example/",
		DeviceKey:  key,
		StatePath:  path,
	}
	state, err := PrepareServe(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("PrepareServe: %v", err)
	}
	if state.DeviceKey != key || state.DeviceID != deviceID {
		t.Errorf("state = %+v", state)
	}
	if state.BifrostURL != "https://bifrost.example" {
		t.Errorf("url should be trimmed, got %q", state.BifrostURL)
	}
	saved, err := LoadDeviceState(path)
	if err != nil || saved.DeviceKey != key {
		t.Errorf("persist failed: %v", err)
	}
	if !strings.Contains(ServeReadyMessage(state, path), state.DeviceID) {
		t.Errorf("ready message should include device id")
	}
	if strings.Contains(ServeReadyMessage(state, path), key) {
		t.Errorf("ready message leaked the device key")
	}
}

func TestPrepareServeRejectsMalformedKey(t *testing.T) {
	cfg := ServeConfig{
		BifrostURL: "https://bifrost.example",
		DeviceKey:  "bfdk_not-a-uuid_" + testSecret,
		StatePath:  testStatePath(t),
	}
	_, err := PrepareServe(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing to serve") {
		t.Fatalf("expected refuse, got: %v", err)
	}
}

func TestPrepareServeReusesPersistedKey(t *testing.T) {
	path := testStatePath(t)
	key := testDeviceKey()
	persisted := DeviceState{
		BifrostURL: "https://bifrost.example",
		DeviceID:   uuid.NewString(),
		DeviceKey:  key,
	}
	if err := SaveDeviceState(path, persisted); err != nil {
		t.Fatal(err)
	}
	cfg := ServeConfig{BifrostURL: "https://bifrost.example", StatePath: path}
	state, err := PrepareServe(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("PrepareServe: %v", err)
	}
	if state.DeviceKey != key {
		t.Errorf("persisted key not reused")
	}
}

func TestPrepareServeDetectsURLMismatch(t *testing.T) {
	path := testStatePath(t)
	persisted := DeviceState{
		BifrostURL: "https://one.example",
		DeviceID:   uuid.NewString(),
		DeviceKey:  testDeviceKey(),
	}
	if err := SaveDeviceState(path, persisted); err != nil {
		t.Fatal(err)
	}
	cfg := ServeConfig{BifrostURL: "https://two.example", StatePath: path}
	_, err := PrepareServe(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "different Bifrost URL") {
		t.Fatalf("expected mismatch error, got: %v", err)
	}
}

func TestPrepareServeEnrollsFirstRun(t *testing.T) {
	token := enrollmentTokenPrefix + uuid.NewString() + "_" + testSecret
	deviceID := uuid.NewString()
	key := deviceKeyPrefix + deviceID + "_" + testSecret
	payload, _ := json.Marshal(map[string]string{
		"device_id":  deviceID,
		"device_key": key,
		"status":     "active",
	})
	srv := newEnrollServer(t, token, http.StatusOK, string(payload))

	path := testStatePath(t)
	cfg := ServeConfig{
		BifrostURL:      srv.URL,
		EnrollmentToken: token,
		StatePath:       path,
	}
	state, err := PrepareServe(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("PrepareServe: %v", err)
	}
	if state.DeviceID != deviceID || state.DeviceKey != key {
		t.Errorf("state = %+v", state)
	}
	saved, err := LoadDeviceState(path)
	if err != nil || saved.DeviceKey != key {
		t.Errorf("state not persisted: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestPrepareServeRefusesWithoutKeyOrToken(t *testing.T) {
	path := testStatePath(t)
	cfg := ServeConfig{
		BifrostURL: "https://bifrost.example",
		StatePath:  path,
	}
	_, err := PrepareServe(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "refusing to serve") ||
		!strings.Contains(msg, "no device key") ||
		!strings.Contains(msg, "no enrollment token") {
		t.Errorf("error should explain the missing inputs: %s", msg)
	}
}

func TestResolveServeConfigPrecedence(t *testing.T) {
	file := ServeConfig{
		BifrostURL:   "https://file.example",
		DeviceKey:    "bfdk_" + uuid.NewString() + "_" + testSecret,
		PollInterval: 30 * time.Second,
		StatePath:    "/tmp/file.json",
		WorkDir:      "/tmp/file-work",
	}
	env := map[string]string{
		"SOPDET_BIFROST_URL": "https://env.example",
		"SOPDET_DEVICE_KEY":  "bfdk_" + uuid.NewString() + "_" + testSecret,
	}
	getenv := func(k string) string { return env[k] }
	flagKey := "bfdk_" + uuid.NewString() + "_" + testSecret
	flags := ServeConfig{
		DeviceKey:    flagKey,
		PollInterval: 5 * time.Second,
		AgentVersion: "1.2.3-flag",
	}

	got := ResolveServeConfig(file, flags, getenv)
	if got.BifrostURL != "https://env.example" {
		t.Errorf("env should override file for url, got %q", got.BifrostURL)
	}
	if got.DeviceKey != flagKey {
		t.Errorf("flag should override env for key")
	}
	if got.PollInterval != 5*time.Second {
		t.Errorf("flag poll interval not applied: %v", got.PollInterval)
	}
	if got.StatePath != "/tmp/file.json" || got.WorkDir != "/tmp/file-work" {
		t.Errorf("file layer lost: %+v", got)
	}
	if got.AgentVersion != "1.2.3-flag" {
		t.Errorf("agent version not carried from the flag layer: %q", got.AgentVersion)
	}
}

func TestResolveServeConfigDisableHints(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		// Unset (and any non-truthy value) keeps the WS hint path enabled.
		{"", true},
		{"0", true},
		{"false", true},
		{"off", true},
		{"no", true},
		// The M6.3 poll-only drill (bifrost#852) selects "on" in any case.
		{"1", false},
		{"true", false},
		{"TRUE", false},
		{"True", false},
		{"yes", false},
		{"YES", false},
		{"on", false},
		{" on ", false},
	}
	for _, tc := range cases {
		env := map[string]string{}
		if tc.env != "" {
			env["SOPDET_DISABLE_HINTS"] = tc.env
		}
		got := ResolveServeConfig(
			ServeConfig{},
			ServeConfig{},
			func(k string) string { return env[k] },
		)
		if got.EnableHints != tc.want {
			t.Errorf(
				"SOPDET_DISABLE_HINTS=%q -> EnableHints=%v, want %v",
				tc.env, got.EnableHints, tc.want,
			)
		}
	}
}

func TestApplyServeDefaults(t *testing.T) {
	cfg := ServeConfig{}
	ApplyServeDefaults(&cfg)
	if cfg.PollInterval != DefaultServePollInterval {
		t.Errorf("poll default = %v", cfg.PollInterval)
	}
	if cfg.StatePath == "" {
		t.Errorf("state path default empty")
	}
}

func TestLoadServeConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.config.json")
	body := `{
		"bifrostUrl": "https://bifrost.example",
		"enrollmentToken": "bfen_` + uuid.NewString() + `_` + testSecret + `",
		"pollInterval": "5s",
		"workDir": "/srv/work"
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServeConfig(path)
	if err != nil {
		t.Fatalf("LoadServeConfig: %v", err)
	}
	if cfg.BifrostURL != "https://bifrost.example" {
		t.Errorf("url = %q", cfg.BifrostURL)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("poll = %v", cfg.PollInterval)
	}
	if cfg.WorkDir != "/srv/work" {
		t.Errorf("workdir = %q", cfg.WorkDir)
	}

	if _, err := LoadServeConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Errorf("explicit missing file should error")
	}
}

func TestValidateBifrostURL(t *testing.T) {
	if err := ValidateBifrostURL(""); err == nil {
		t.Error("empty should error")
	}
	if err := ValidateBifrostURL("ftp://x"); err == nil {
		t.Error("ftp should error")
	}
	if err := ValidateBifrostURL("http://example.com"); err == nil {
		t.Error("plain http to non-loopback must be rejected for credential-bearing traffic")
	}
	if err := ValidateBifrostURL("http://127.0.0.1:8443/path/"); err != nil {
		t.Errorf("loopback http should be allowed (dev/test): %v", err)
	}
	if err := ValidateBifrostURL("http://localhost/path/"); err != nil {
		t.Errorf("localhost http should be allowed (dev/test): %v", err)
	}
	if err := ValidateBifrostURL("https://bifrost.example/path/"); err != nil {
		t.Errorf("valid url rejected: %v", err)
	}
}

func TestPrepareServeRefusesUnwritableStateBeforeEnrolling(t *testing.T) {
	token := enrollmentTokenPrefix + uuid.NewString() + "_" + testSecret
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// Make the state directory component a regular file so MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ServeConfig{
		BifrostURL:      srv.URL,
		EnrollmentToken: token,
		StatePath:       filepath.Join(blocker, "serve.json"),
	}
	_, err := PrepareServe(context.Background(), cfg, srv.Client())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "token not consumed") {
		t.Errorf("error should state the token was not consumed: %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaked token: %v", err)
	}
	if hits != 0 {
		t.Errorf("enroll must not be attempted before the state path is writable; hits = %d", hits)
	}
}

func TestKeyFormatHelpers(t *testing.T) {
	key := testDeviceKey()
	if !ValidDeviceKeyFormat(key) {
		t.Errorf("valid key rejected")
	}
	id, ok := ParseDeviceKeyID(key)
	if !ok || id == "" {
		t.Errorf("id parse failed")
	}
	if _, ok := ParseDeviceKeyID(controlKeyPrefix + uuid.NewString() + "_" + testSecret); ok {
		t.Errorf("control key should not parse as device key")
	}
	if ValidDeviceKeyFormat("short") {
		t.Errorf("short accepted")
	}
	if ValidDeviceKeyFormat(deviceKeyPrefix + strings.ToUpper(uuid.NewString()) + "_" + testSecret) {
		t.Errorf("uppercase uuid should be rejected (platform format is lowercase)")
	}
}
