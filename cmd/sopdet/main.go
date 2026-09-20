// Command sopdet is a read-only device inventory collector.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Midtown-Technology-Group/sopdet/internal/app"
	"github.com/Midtown-Technology-Group/sopdet/internal/config"
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
	flag.Parse()

	if showVer {
		fmt.Println(Version)
		return
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

	res, err := app.Run(context.Background(), cfg, Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run error: %v\n", err)
		os.Exit(1)
	}
	if cfg.Endpoint != "" && !cfg.DryRun {
		fmt.Fprintf(os.Stderr, "scan=%s action=%s delivered=%v chunks=%d spooled=%d\n",
			res.Envelope.ScanID, res.Envelope.Action, res.Delivered, res.Chunks, res.Spooled)
		if !res.Delivered {
			os.Exit(3)
		}
	}
}
