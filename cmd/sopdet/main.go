// Command sopdet is a read-only device inventory collector.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/Midtown-Technology-Group/sopdet/internal/agent"
	"github.com/Midtown-Technology-Group/sopdet/internal/app"
	"github.com/Midtown-Technology-Group/sopdet/internal/config"
	"github.com/Midtown-Technology-Group/sopdet/internal/progress"
	"github.com/Midtown-Technology-Group/sopdet/internal/term"
	"github.com/Midtown-Technology-Group/sopdet/internal/ui"
)

// Version is overridden at build time with -ldflags "-X main.Version=...".
var Version = "0.1.0-dev"

func main() {
	var (
		cfgPath    string
		endpoint   string
		apiKey     string
		profile    string
		outputPath string
		proxy      string
		statePath  string
		compress   bool
		delta      bool
		dryRun     bool
		incAppx    bool
		incProcs   bool
		showVer    bool
		uiFlag     bool
		uiPort     int
		noBrowser  bool
		quiet      bool

		// serve mode (device control plane, epic #818 / M3 #822)
		serve          bool
		serveCfgPath   string
		bifrostURL     string
		deviceKey      string
		enrollToken    string
		serveStatePath string
		workDir        string
		pollInterval   time.Duration
	)
	flag.StringVar(&cfgPath, "config", "", "path to inventory.config.json (default: alongside the binary)")
	flag.StringVar(&endpoint, "endpoint", "", "Bifrost ingest endpoint URL")
	flag.StringVar(&apiKey, "api-key", "", "per-engagement ingest key (X-Bifrost-Key)")
	flag.StringVar(&profile, "profile", "", "minimal|quick|full")
	flag.StringVar(&outputPath, "out", "", "write the envelope to this file")
	flag.StringVar(&proxy, "proxy", "", "explicit proxy URL")
	flag.StringVar(&statePath, "state", "", "delta state file path")
	flag.BoolVar(&compress, "compress", false, "gzip+base64 the payload")
	flag.BoolVar(&delta, "delta", false, "send only changes after a baseline snapshot")
	flag.BoolVar(&dryRun, "dry-run", false, "collect only; never post")
	flag.BoolVar(&incAppx, "include-appx", false, "include Store/UWP packages")
	flag.BoolVar(&incProcs, "include-processes", false, "include running processes")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.BoolVar(&uiFlag, "ui", false, "serve a local browser progress page for this run")
	flag.IntVar(&uiPort, "ui-port", 0, "fixed port for the progress page (0 = random)")
	flag.BoolVar(&noBrowser, "no-browser", false, "do not auto-open the progress page")
	flag.BoolVar(&quiet, "quiet", false, "suppress the banner and per-entity progress")
	flag.BoolVar(&serve, "serve", false, "resident serve mode: enroll/hold device identity and (later) run ad-hoc jobs")
	flag.StringVar(&serveCfgPath, "serve-config", "", "path to serve config JSON (flags > env > file)")
	flag.StringVar(&bifrostURL, "bifrost-url", "", "Bifrost base URL for serve mode (env SOPDET_BIFROST_URL)")
	flag.StringVar(&deviceKey, "device-key", "", "device key (env SOPDET_DEVICE_KEY); secret, never logged")
	flag.StringVar(&enrollToken, "enroll-token", "", "one-time enrollment token (env SOPDET_ENROLLMENT_TOKEN); secret, never logged")
	flag.StringVar(&serveStatePath, "serve-state", "", "path to persisted device state (env SOPDET_SERVE_STATE)")
	flag.StringVar(&workDir, "work-dir", "", "working directory for script temp files (env SOPDET_WORK_DIR)")
	flag.DurationVar(&pollInterval, "poll-interval", 0, "HTTP claim poll interval while WS is down (env SOPDET_POLL_INTERVAL, default 10s)")
	flag.Parse()

	if showVer {
		fmt.Println(Version)
		return
	}

	if serve {
		flags := agent.ServeConfig{
			BifrostURL:      bifrostURL,
			DeviceKey:       deviceKey,
			EnrollmentToken: enrollToken,
			StatePath:       serveStatePath,
			PollInterval:    pollInterval,
			WorkDir:         workDir,
		}
		os.Exit(runServe(serveCfgPath, flags))
	}

	if cfgPath == "" {
		if exe, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(exe), "inventory.config.json")
			if _, err := os.Stat(candidate); err == nil {
				cfgPath = candidate
			}
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "endpoint":
			cfg.Endpoint = endpoint
		case "api-key":
			cfg.APIKey = apiKey
		case "profile":
			cfg.Profile = profile
		case "out":
			cfg.OutputPath = outputPath
		case "proxy":
			cfg.Proxy = proxy
		case "state":
			cfg.StatePath = statePath
		case "compress":
			cfg.Compress = compress
		case "delta":
			cfg.Delta = delta
		case "dry-run":
			cfg.DryRun = dryRun
		case "include-appx":
			cfg.IncludeAppx = incAppx
		case "include-processes":
			cfg.IncludeProcesses = incProcs
		}
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	tty := term.NewReporter(os.Stdout, term.Options{Version: Version, Quiet: quiet})
	sinks := []progress.Sink{tty}

	var srv *ui.Server
	if uiFlag {
		s, err := ui.New(ui.Options{Port: uiPort})
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui error: %v\n", err)
		} else {
			srv = s
			sinks = append(sinks, srv)
			go srv.Serve()
			fmt.Fprintf(os.Stderr, "progress UI: %s\n", srv.URL())
			if !noBrowser {
				if err := ui.OpenBrowser(srv.URL()); err != nil {
					fmt.Fprintln(os.Stderr, "open the URL above to watch progress")
				}
			}
		}
	}
	rep := progress.Multi(sinks...)

	res, err := app.Run(ctx, cfg, Version, rep)
	if err != nil {
		rep.Emit(progress.Event{Kind: progress.KindError, Message: err.Error()})
		fmt.Fprintf(os.Stderr, "run error: %v\n", err)
		linger(srv)
		os.Exit(1)
	}

	linger(srv)

	if cfg.Endpoint != "" && !cfg.DryRun && !res.Delivered {
		os.Exit(3)
	}
}

// linger keeps an open progress page alive briefly so the final state is
// readable, then shuts the server down.
func linger(srv *ui.Server) {
	if srv == nil {
		return
	}
	srv.WaitForViewers(context.Background(), 15*time.Minute, 6*time.Second)
	_ = srv.Close()
}

// runServe prepares the device identity for serve mode (M3.1 #838) and
// reports readiness without ever printing secrets. The claim/run loop lands
// with M3.5 (#842).
func runServe(serveCfgPath string, flags agent.ServeConfig) int {
	fileCfg, err := agent.LoadServeConfig(serveCfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve config error: %v\n", err)
		return 2
	}
	cfg := agent.ResolveServeConfig(fileCfg, flags, os.Getenv)
	agent.ApplyServeDefaults(&cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	state, err := agent.PrepareServe(ctx, cfg, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	fmt.Fprintln(os.Stderr, agent.ServeReadyMessage(state, cfg.StatePath))
	srv, err := agent.NewServe(cfg, state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve error: %v\n", err)
		return 2
	}
	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "serve error: %v\n", err)
		return 1
	}
	return 0
}
