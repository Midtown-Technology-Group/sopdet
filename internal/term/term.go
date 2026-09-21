// Package term renders the progress event stream as branded console output.
// It degrades to plain, one-line-per-event log output when stdout is not a
// terminal, so the same code path serves interactive and piped runs.
package term

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Midtown-Technology-Group/sopdet/internal/progress"
)

// Options configures a Reporter.
type Options struct {
	Version string // shown in the banner
	Quiet   bool   // suppress the banner and per-entity lines
}

// Reporter writes branded progress to a single writer.
type Reporter struct {
	out     io.Writer
	version string
	quiet   bool
	color   bool
	tty     bool

	total   int
	lastLen int
	start   time.Time
}

// NewReporter builds a terminal reporter writing to out.
func NewReporter(out io.Writer, o Options) *Reporter {
	tty := isTerminal(out)
	return &Reporter{
		out:     out,
		version: o.Version,
		quiet:   o.Quiet,
		tty:     tty,
		color:   tty && enableVirtualTerminal() && colorAllowed(),
		start:   time.Now(),
	}
}

// Emit renders one event.
func (r *Reporter) Emit(e progress.Event) {
	switch e.Kind {
	case progress.KindStart:
		r.banner(e)
	case progress.KindPlan:
		r.total = e.Total
		if !r.quiet {
			r.line("%s  collecting %d entities", r.dim("plan"), e.Total)
		}
	case progress.KindEntity:
		r.entity(e)
	case progress.KindBudget:
		r.budget(e)
	case progress.KindDeliver:
		r.deliver(e)
	case progress.KindDone:
		r.done(e)
	case progress.KindError:
		r.endLine()
		r.line("%s %s", r.red("error"), e.Message)
	}
}

func (r *Reporter) banner(e progress.Event) {
	if r.quiet {
		return
	}
	ver := r.version
	if ver == "" {
		ver = "dev"
	}
	host, _ := e.Data["hostname"].(string)
	profile, _ := e.Data["profile"].(string)
	source, _ := e.Data["source"].(string)
	fmt.Fprintln(r.out)
	r.line("%s", r.accent("  ███████╗ ██████╗ ██████╗ ██████╗ ███████╗████████╗"))
	r.line("%s", r.accent("  ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝╚══██╔══╝"))
	r.line("%s", r.accent("  ███████╗██║   ██║██████╔╝██║  ██║█████╗     ██║   "))
	r.line("%s", r.accent("  ╚════██║██║   ██║██╔═══╝ ██║  ██║██╔══╝     ██║   "))
	r.line("%s", r.accent("  ███████║╚██████╔╝██║     ██████╔╝███████╗   ██║   "))
	r.line("%s", r.accent("  ╚══════╝ ╚═════╝ ╚═╝     ╚═════╝ ╚══════╝   ╚═╝   "))
	r.line("  %s  %s", r.dim("device inventory"), r.dim("v"+ver))
	fmt.Fprintln(r.out)
	r.line("  %s %s  %s %s  %s %s",
		r.dim("host"), host, r.dim("profile"), profile, r.dim("id"), source)
	fmt.Fprintln(r.out)
}

func (r *Reporter) entity(e progress.Event) {
	if r.quiet {
		return
	}
	label := pretty(e.Entity)
	if r.tty {
		bar := r.bar(e.Index, e.Total)
		status := r.green(fmt.Sprintf("%d", e.Count))
		if e.OK != nil && !*e.OK {
			status = r.red("failed")
		}
		r.rewrite("  %s  %s %-22s %s", bar, r.dim(fmt.Sprintf("%d/%d", e.Index, e.Total)), label, status)
		if e.Index >= e.Total {
			r.endLine()
		}
		return
	}
	if e.OK != nil && !*e.OK {
		r.line("  [%d/%d] %s: %s", e.Index, e.Total, label, e.Message)
		return
	}
	r.line("  [%d/%d] %s: %d records (%dms)", e.Index, e.Total, label, e.Count, e.Ms)
}

func (r *Reporter) budget(e progress.Event) {
	r.endLine()
	list, _ := e.Data["truncated"].([]string)
	if len(list) == 0 {
		return
	}
	r.line("%s  payload trimmed to budget: %s", r.dim("note"), strings.Join(list, ", "))
}

func (r *Reporter) deliver(e progress.Event) {
	r.endLine()
	dry, _ := e.Data["dry_run"].(bool)
	if dry {
		r.line("%s  collected only (dry run)", r.dim("send"))
		return
	}
	delivered, _ := e.Data["delivered"].(bool)
	chunks, _ := e.Data["chunks"].(int)
	spooled, _ := e.Data["spooled"].(int)
	mark := r.green("delivered")
	if !delivered {
		mark = r.red("not delivered")
	}
	r.line("%s  %s  chunks=%d spooled=%d", r.dim("send"), mark, chunks, spooled)
}

func (r *Reporter) done(e progress.Event) {
	r.endLine()
	n, _ := e.Data["entities"].(int)
	errs, _ := e.Data["entity_errors"].(int)
	scan, _ := e.Data["scan_id"].(string)
	action, _ := e.Data["action"].(string)
	partial, _ := e.Data["partial"].(bool)
	elapsed := time.Since(r.start).Round(time.Millisecond)

	tag := r.green("complete")
	if errs > 0 {
		tag = r.accent("complete")
	}
	r.line("")
	r.line("  %s  %s  %s  %s", tag,
		r.dim(fmt.Sprintf("entities=%d errors=%d", n, errs)),
		r.dim(fmt.Sprintf("action=%s", action)),
		r.dim(elapsed.String()))
	if partial {
		r.line("  %s", r.dim("partial snapshot (not a full profile)"))
	}
	r.line("  %s", r.dim("scan "+scan))
}

// -- rendering helpers -------------------------------------------------------

// bar builds an ASCII progress meter like [=====----------].
func (r *Reporter) bar(i, total int) string {
	const width = 22
	if total <= 0 {
		total = 1
	}
	if i > total {
		i = total
	}
	fill := i * width / total
	if fill < 0 {
		fill = 0
	}
	if fill > width {
		fill = width
	}
	mid := r.accent(strings.Repeat("=", fill)) + strings.Repeat("-", width-fill)
	return r.accent("[") + mid + r.accent("]")
}

func (r *Reporter) line(format string, args ...any) {
	fmt.Fprintf(r.out, format+"\n", args...)
}

func (r *Reporter) rewrite(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	pad := ""
	if n := r.lastLen - visibleLen(s); n > 0 {
		pad = strings.Repeat(" ", n)
	}
	fmt.Fprintf(r.out, "\r%s%s", s, pad)
	r.lastLen = visibleLen(s)
}

func (r *Reporter) endLine() {
	if !r.tty || r.lastLen == 0 {
		return
	}
	fmt.Fprint(r.out, "\r"+strings.Repeat(" ", r.lastLen)+"\r")
	r.lastLen = 0
}

func (r *Reporter) paint(code, s string) string {
	if !r.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (r *Reporter) accent(s string) string { return r.paint("38;5;220", s) }
func (r *Reporter) green(s string) string  { return r.paint("32", s) }
func (r *Reporter) red(s string) string    { return r.paint("31", s) }
func (r *Reporter) dim(s string) string    { return r.paint("2", s) }

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func colorAllowed() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	return true
}

// visibleLen counts runes minus any ANSI escape sequences.
func visibleLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case esc:
			if r == 'm' {
				esc = false
			}
		case r == '\x1b':
			esc = true
		default:
			n++
		}
	}
	return n
}

// pretty turns an entity key into a friendlier label.
func pretty(name string) string {
	labels := map[string]string{
		"os": "operating system", "os_patches": "OS patches", "appx_packages": "Store packages",
		"network_interfaces": "network", "memory_modules": "memory", "local_users": "local users",
		"logged_on_users": "logged-on users", "firewall_profiles": "firewall", "antivirus_threats": "AV threats",
		"listening_ports": "listening ports", "startup_items": "startup items", "scheduled_tasks": "scheduled tasks",
		"tpm": "TPM", "bios": "BIOS", "secureboot": "Secure Boot",
	}
	if l, ok := labels[name]; ok {
		return l
	}
	return strings.ReplaceAll(name, "_", " ")
}
