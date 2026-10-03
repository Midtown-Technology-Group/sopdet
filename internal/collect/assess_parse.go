// Package collect parsers for the assessment entities.
//
// assess_parse.go holds portable, pure parsing helpers shared by the
// platform collectors. Every function here is covered by assess_parse_test.go
// and runs on any OS; platform files only gather command/file output.
package collect

import (
	"encoding/csv"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// WifiAssociation is one wireless interface's link state. Nothing is scanned;
// this reflects the current association only.
type WifiAssociation struct {
	Interface      string
	State          string
	SSID           string
	BSSID          string
	SignalPercent  *int
	SignalDbm      *int
	RadioType      string
	Authentication string
	Cipher         string
	Channel        *int
}

// parseNetshWLANInterfaces parses `netsh wlan show interfaces` output.
func parseNetshWLANInterfaces(out string) []WifiAssociation {
	var result []WifiAssociation
	for _, block := range strings.Split(out, "\n\n") {
		kv := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := cutColon(line)
			if !ok {
				continue
			}
			kv[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
		name := kv["name"]
		if name == "" {
			continue
		}
		w := WifiAssociation{
			Interface:      name,
			State:          kv["state"],
			SSID:           kv["ssid"],
			BSSID:          kv["bssid"],
			RadioType:      kv["radio type"],
			Authentication: kv["authentication"],
			Cipher:         kv["cipher"],
		}
		if s := strings.TrimSuffix(kv["signal"], "%"); s != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				w.SignalPercent = &n
			}
		}
		if s := kv["channel"]; s != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				w.Channel = &n
			}
		}
		result = append(result, w)
	}
	return result
}

func cutColon(line string) (string, string, bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", "", false
	}
	return line[:i], line[i+1:], true
}

// WinhttpProxy is the system (WinHTTP) proxy configuration.
type WinhttpProxy struct {
	Direct bool
	Server string
	Bypass string
}

// parseNetshWinhttpProxy parses `netsh winhttp show proxy` output.
func parseNetshWinhttpProxy(out string) WinhttpProxy {
	lower := strings.ToLower(out)
	if strings.Contains(lower, "direct access (no proxy server)") {
		return WinhttpProxy{Direct: true}
	}
	var p WinhttpProxy
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := cutColon(line)
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "proxy server(s)":
			p.Server = strings.TrimSpace(v)
		case "bypass list":
			p.Bypass = strings.TrimSpace(v)
		}
	}
	if p.Server == "" {
		p.Direct = true
	}
	return p
}

// RouteEntry is one IPv4 route table row.
type RouteEntry struct {
	Destination string
	Mask        string
	Gateway     string
	Interface   string
	Metric      *int
	Persistent  bool
}

func intPtr(n int) *int { return &n }

// parseRoutePrint4 parses Windows `route print -4` (active + persistent).
func parseRoutePrint4(out string) []RouteEntry {
	var result []RouteEntry
	persistent := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		lower := strings.ToLower(t)
		if strings.Contains(lower, "persistent routes") {
			persistent = true
			continue
		}
		if strings.Contains(lower, "active routes") {
			persistent = false
			continue
		}
		f := strings.Fields(t)
		if len(f) < 4 {
			continue
		}
		if !isIPv4(f[0]) || !isIPv4(f[1]) {
			continue
		}
		gw := f[2]
		if strings.EqualFold(gw, "on-link") {
			gw = ""
		} else if !isIPv4(gw) {
			continue
		}
		r := RouteEntry{Destination: f[0], Mask: f[1], Gateway: gw, Persistent: persistent}
		if persistent {
			// Persistent section: destination, mask, gateway, metric.
			if n, err := strconv.Atoi(f[3]); err == nil {
				r.Metric = intPtr(n)
			}
		} else {
			// Active section: destination, mask, gateway, interface, metric.
			if len(f) < 5 || !isIPv4(f[3]) {
				continue
			}
			r.Interface = f[3]
			if n, err := strconv.Atoi(f[4]); err == nil {
				r.Metric = intPtr(n)
			}
		}
		result = append(result, r)
	}
	return result
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// parseProcNetRoute parses Linux /proc/net/route (hex, little-endian).
func parseProcNetRoute(content string) []RouteEntry {
	var result []RouteEntry
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[0] == "Iface" {
			continue
		}
		dst := hexLEIPv4(f[1])
		gw := hexLEIPv4(f[2])
		mask := hexLEIPv4(f[7])
		if dst == "" || gw == "" || mask == "" {
			continue
		}
		r := RouteEntry{Destination: dst, Mask: mask, Gateway: gw, Interface: f[0]}
		if n, err := strconv.Atoi(f[6]); err == nil {
			r.Metric = intPtr(n)
		}
		result = append(result, r)
	}
	return result
}

// hexLEIPv4 decodes a little-endian hex IPv4 address like 0101A8C0.
func hexLEIPv4(s string) string {
	if len(s) != 8 {
		return ""
	}
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		n, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		b[3-i] = byte(n)
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

var netstatRouteLine = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)`)

// parseNetstatInetRoutes parses macOS/BSD `netstat -rn -f inet` output.
// Link-local gateway rows (link#N) are skipped; Netif becomes Interface.
func parseNetstatInetRoutes(out string) []RouteEntry {
	var result []RouteEntry
	for _, line := range strings.Split(out, "\n") {
		m := netstatRouteLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		dst, gw, _, iface := m[1], m[2], m[3], m[4]
		if strings.HasPrefix(gw, "link#") || dst == "Destination" {
			continue
		}
		if !isIPv4(gw) && gw != "default" {
			// Destination may carry /bits; gateway must be an IP.
			if !strings.Contains(dst, ".") && dst != "default" {
				continue
			}
		}
		if !isIPv4(gw) {
			continue
		}
		dest := dst
		mask := ""
		if i := strings.Index(dst, "/"); i >= 0 {
			dest = dst[:i]
			mask = dst[i+1:]
		}
		if dest == "default" {
			dest, mask = "0.0.0.0", "0"
		}
		result = append(result, RouteEntry{
			Destination: dest, Mask: mask, Gateway: gw, Interface: iface,
		})
	}
	return result
}

// ArpNeighbor is one neighbor table row. Nothing is probed.
type ArpNeighbor struct {
	IP    string
	MAC   string
	Iface string
	Type  string // static | dynamic
	State string // platform detail (Linux); empty elsewhere
}

// parseArpAWindows parses Windows `arp -a` output.
func parseArpAWindows(out string) []ArpNeighbor {
	var result []ArpNeighbor
	iface := ""
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(t), "interface:") {
			if f := strings.Fields(t); len(f) >= 2 {
				iface = f[1]
			}
			continue
		}
		f := strings.Fields(t)
		if len(f) != 3 || !isIPv4(f[0]) {
			continue
		}
		typ := strings.ToLower(f[2])
		if typ != "static" && typ != "dynamic" {
			continue
		}
		result = append(result, ArpNeighbor{IP: f[0], MAC: f[1], Iface: iface, Type: typ})
	}
	return result
}

var arpDarwinLine = regexp.MustCompile(`^\S+\s+\((\S+)\)\s+at\s+(\S+)\s+on\s+(\S+)`)

// parseArpADarwin parses macOS/BSD `arp -a` output.
func parseArpADarwin(out string) []ArpNeighbor {
	var result []ArpNeighbor
	for _, line := range strings.Split(out, "\n") {
		m := arpDarwinLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		if !isIPv4(m[1]) || m[2] == "(incomplete)" {
			continue
		}
		typ := "dynamic"
		if strings.Contains(line, "permanent") {
			typ = "static"
		}
		result = append(result, ArpNeighbor{IP: m[1], MAC: m[2], Iface: m[3], Type: typ})
	}
	return result
}

// parseProcNetArp parses Linux /proc/net/arp.
func parseProcNetArp(content string) []ArpNeighbor {
	var result []ArpNeighbor
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[0] == "IP" || !isIPv4(f[0]) {
			continue
		}
		flags, err := strconv.ParseUint(f[2], 0, 32)
		if err != nil || flags == 0 {
			continue // incomplete entry
		}
		if f[3] == "00:00:00:00:00:00" {
			continue
		}
		typ := "dynamic"
		if flags&0x4 != 0 {
			typ = "static"
		}
		result = append(result, ArpNeighbor{
			IP: f[0], MAC: f[3], Iface: f[5], Type: typ, State: arpFlagName(flags),
		})
	}
	return result
}

func arpFlagName(flags uint64) string {
	switch flags {
	case 0x2:
		return "reachable"
	case 0x4:
		return "permanent"
	case 0x6:
		return "stale"
	default:
		return "0x" + strconv.FormatUint(flags, 16)
	}
}

// ScheduledTaskRow is one verbose schtasks row. Header names localize; the
// parser matches English headers and falls back to column positions.
type ScheduledTaskRow struct {
	TaskName    string
	Status      string
	Enabled     *bool
	LastRun     string
	LastResult  string
	NextRun     string
	Author      string
	Command     string
	RunAsUser   string
	LogonMode   string
	Schedule    string
	ScheduleTyp string
}

// parseSchtasksCSV parses `schtasks /query /fo csv /v` output. schtasks can
// emit non-CSV ERROR lines; the header row is located by its TaskName first
// column and anything else is skipped.
func parseSchtasksCSV(out string) []ScheduledTaskRow {
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil {
		return nil
	}
	header := -1
	for i, rec := range records {
		if len(rec) == 0 {
			continue
		}
		// schtasks prepends a UTF-8 BOM to redirected output; strip it
		// (plus quotes/space) before matching the header column.
		first := strings.Trim(strings.TrimSpace(rec[0]), "\"\ufeff \t")
		if strings.EqualFold(first, "taskname") {
			header = i
			break
		}
	}
	if header < 0 || header+1 >= len(records) {
		return nil
	}
	col := map[string]int{}
	for i, h := range records[header] {
		col[strings.ToLower(strings.TrimSpace(strings.Trim(h, "\"")))] = i
	}
	at := func(rec []string, name string, fallback int) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		if fallback >= 0 && fallback < len(rec) {
			return strings.TrimSpace(rec[fallback])
		}
		return ""
	}
	var result []ScheduledTaskRow
	for _, rec := range records[header+1:] {
		name := at(rec, "taskname", 0)
		if name == "" || !strings.HasPrefix(name, `\`) {
			continue
		}
		row := ScheduledTaskRow{
			TaskName:    name,
			Status:      at(rec, "status", -1),
			LastRun:     at(rec, "last run time", -1),
			LastResult:  at(rec, "last result", -1),
			NextRun:     at(rec, "next run time", -1),
			Author:      at(rec, "author", -1),
			Command:     at(rec, "task to run", -1),
			RunAsUser:   at(rec, "run as user", -1),
			LogonMode:   at(rec, "logon mode", -1),
			Schedule:    at(rec, "schedule", -1),
			ScheduleTyp: at(rec, "schedule type", -1),
		}
		if s := at(rec, "scheduled task state", -1); s != "" {
			enabled := strings.EqualFold(s, "enabled")
			row.Enabled = &enabled
		}
		result = append(result, row)
	}
	return result
}

// parseNetLocalgroup parses `net localgroup <group>` member lines.
func parseNetLocalgroup(out string) []string {
	var members []string
	inMembers := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if !inMembers {
			if strings.HasPrefix(t, "---") {
				inMembers = true
			}
			continue
		}
		if t == "" || strings.HasPrefix(t, "The command completed") {
			break
		}
		members = append(members, t)
	}
	return members
}

// parseNetAccounts parses `net accounts` output into raw key/value text.
// Keys are lowercased; values are unparsed (callers interpret numbers).
func parseNetAccounts(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		// Two-or-more-space separator between key and value.
		parts := regexp.MustCompile(`\s{2,}`).Split(strings.TrimSpace(line), 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parts[0]), ":"))
		m[key] = strings.TrimSpace(parts[1])
	}
	return m
}

// accountInt interprets a `net accounts` value: numbers parse, everything
// else (Never, Unlimited, None) is unlimited and reported as null.
func accountInt(v string) *int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	// Strip parentheticals like "42 (days)" defensively.
	if i := strings.Index(v, " "); i >= 0 {
		v = v[:i]
	}
	v = strings.ReplaceAll(v, ",", "")
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return &n
}

// LastSummary counts reboot/shutdown/crash lines from `last`.
type LastSummary struct {
	Reboots      int
	Shutdowns    int
	Crashes      int
	LastCrash    string // ISO-8601 with the current year (wtmp has no year)
	LastReboot   string
	LastShutdown string
}

var lastDateRe = regexp.MustCompile(`([A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d+ \d+:\d+)`)

// parseLastWTMP parses `last -x` (Linux) or `last reboot shutdown` (macOS).
// It mirrors the Windows reliability counters closely enough for one entity.
func parseLastWTMP(out string, year int) LastSummary {
	var s LastSummary
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "wtmp begins") {
			continue
		}
		lower := strings.ToLower(t)
		kind := ""
		switch {
		case strings.HasPrefix(lower, "reboot"):
			kind = "reboot"
			s.Reboots++
		case strings.HasPrefix(lower, "shutdown"):
			kind = "shutdown"
			s.Shutdowns++
		case strings.Contains(lower, "crash"):
			kind = "crash"
			s.Crashes++
		default:
			continue
		}
		if m := lastDateRe.FindString(t); m != "" {
			if ts, err := parseLastDate(m, year); err == nil {
				switch kind {
				case "reboot":
					s.LastReboot = ts
				case "shutdown":
					s.LastShutdown = ts
				case "crash":
					s.LastCrash = ts
				}
			}
		}
	}
	return s
}

func parseLastDate(s string, year int) (string, error) {
	// wtmp dates look like "Mon Oct  3 09:15" with no year or zone; the
	// caller supplies the current year and the value is stamped UTC.
	t, err := time.Parse("Mon Jan _2 15:04", s)
	if err != nil {
		return "", err
	}
	stamped := time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
	return stamped.Format(time.RFC3339), nil
}

// SystemdTimer is one `systemctl list-timers` row.
type SystemdTimer struct {
	Unit      string
	Activates string
	Next      string
	Last      string
}

var systemctlDateRe = regexp.MustCompile(`[A-Z][a-z]{2} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+`)

// parseSystemctlTimers parses `systemctl list-timers --all --no-pager`.
// Columns are positional from the right (unit, activates); datetimes are
// matched by shape so variable-width LEFT/PASSED columns cannot shift them.
func parseSystemctlTimers(out string) []SystemdTimer {
	var result []SystemdTimer
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "NEXT") || strings.Contains(t, "timers listed") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 3 {
			continue
		}
		unit := f[len(f)-2]
		activates := f[len(f)-1]
		if !strings.HasSuffix(unit, ".timer") {
			continue
		}
		dates := systemctlDateRe.FindAllString(t, -1)
		st := SystemdTimer{Unit: unit, Activates: activates}
		if len(dates) > 0 {
			st.Next = dates[0]
		}
		if len(dates) > 1 {
			st.Last = dates[1]
		}
		result = append(result, st)
	}
	return result
}

// LaunchdJob is one `launchctl list` row.
type LaunchdJob struct {
	Label  string
	PID    string
	Status string
}

// parseLaunchctlList parses macOS `launchctl list` output.
func parseLaunchctlList(out string) []LaunchdJob {
	var result []LaunchdJob
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 3 || f[0] == "PID" {
			continue
		}
		result = append(result, LaunchdJob{PID: f[0], Status: f[1], Label: f[2]})
	}
	return result
}

// CronEntry is one crontab job line.
type CronEntry struct {
	Schedule string
	User     string
	Command  string
	LineNo   int
}

// parseCrontabFile parses a crontab file. System crontabs (crontab, cron.d)
// carry a user field; user crontabs do not.
func parseCrontabFile(content string, hasUser bool) []CronEntry {
	var result []CronEntry
	for i, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if cronEnvAssign(t) {
			continue
		}
		f := strings.Fields(t)
		if strings.HasPrefix(t, "@") {
			if len(f) < 2 {
				continue
			}
			e := CronEntry{Schedule: f[0], LineNo: i + 1}
			rest := f[1:]
			if hasUser {
				if len(rest) < 2 {
					continue
				}
				e.User, rest = rest[0], rest[1:]
			}
			e.Command = strings.Join(rest, " ")
			result = append(result, e)
			continue
		}
		if len(f) < 6 {
			continue
		}
		e := CronEntry{Schedule: strings.Join(f[:5], " "), LineNo: i + 1}
		rest := f[5:]
		if hasUser {
			if len(rest) < 2 {
				continue
			}
			e.User, rest = rest[0], rest[1:]
		}
		e.Command = strings.Join(rest, " ")
		result = append(result, e)
	}
	return result
}

var cronEnvRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func cronEnvAssign(line string) bool { return cronEnvRe.MatchString(line) }

// ResolvConf is the parsed /etc/resolv.conf.
type ResolvConf struct {
	Servers []string
	Domain  string
}

// parseResolvConf parses nameserver/search/domain lines.
func parseResolvConf(content string) ResolvConf {
	var r ResolvConf
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch f[0] {
		case "nameserver":
			if ip := net.ParseIP(f[1]); ip != nil {
				r.Servers = append(r.Servers, f[1])
			}
		case "search":
			if r.Domain == "" {
				r.Domain = f[1]
			}
		case "domain":
			if r.Domain == "" {
				r.Domain = f[1]
			}
		}
	}
	return r
}

// DotnetRuntime is one `dotnet --list-runtimes` row.
type DotnetRuntime struct {
	Name    string
	Version string
	Path    string
}

// parseDotnetRuntimes parses `dotnet --list-runtimes` output.
func parseDotnetRuntimes(out string) []DotnetRuntime {
	var result []DotnetRuntime
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 3 {
			continue
		}
		path := strings.Trim(f[2], "[]")
		if !strings.Contains(f[1], ".") {
			continue
		}
		result = append(result, DotnetRuntime{Name: f[0], Version: f[1], Path: path})
	}
	return result
}

// parseSshdConfig parses sshd_config with first-effective-wins semantics and
// stops at the first Match block (conditional stanzas are out of scope).
func parseSshdConfig(content string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 {
			continue
		}
		if strings.EqualFold(f[0], "match") {
			break
		}
		k := strings.ToLower(f[0])
		if _, seen := m[k]; seen {
			continue
		}
		m[k] = f[1]
	}
	return m
}

// parseLoginDefs parses /etc/login.defs KEY value lines.
func parseLoginDefs(content string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 {
			continue
		}
		m[strings.ToUpper(f[0])] = f[1]
	}
	return m
}

// QuserSession is one `quser` row. The row shape mirrors the PowerShell
// collector's regex so both implementations emit identical records.
type QuserSession struct {
	User      string
	Session   string
	ID        string
	State     string
	LogonTime string
}

var quserRowRe = regexp.MustCompile(`^\s*>?\s*(\S+)\s+(console|rdp-tcp#?\d*)\s+(\d+)\s+(\S+)\s+(\S+)\s*(.*)$`)

// parseQuser parses `quser` output, skipping the header and none/disc states.
func parseQuser(out string) []QuserSession {
	var result []QuserSession
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimRight(line, "\r\n")
		if regexp.MustCompile(`^\s*>?\s*USERNAME`).MatchString(t) {
			continue
		}
		m := quserRowRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		state := m[4]
		if regexp.MustCompile(`^(?i)(none|disc)$`).MatchString(state) {
			continue
		}
		logon := strings.TrimSpace(state + " " + m[5] + " " + m[6])
		result = append(result, QuserSession{
			User: m[1], Session: m[2], ID: m[3], State: state, LogonTime: logon,
		})
	}
	return result
}

// parseReagentcInfo extracts the Windows RE status line.
func parseReagentcInfo(out string) string {
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if !strings.Contains(lower, "windows re status") {
			continue
		}
		// Check disabled first: it contains "abled".
		if strings.Contains(lower, "disabled") {
			return "Disabled"
		}
		if strings.Contains(lower, "enabled") {
			return "Enabled"
		}
	}
	return "unknown"
}

var plistDateRe = regexp.MustCompile(`<date>([^<]+)</date>`)

// parseMacInstallHistory scans InstallHistory.plist XML for <date> entries
// and returns the latest timestamp and the entry count.
func parseMacInstallHistory(content string) (string, int) {
	matches := plistDateRe.FindAllStringSubmatch(content, -1)
	latest := ""
	for _, m := range matches {
		if m[1] > latest {
			latest = m[1]
		}
	}
	return latest, len(matches)
}

// parsePwpolicyAccountPolicies extracts a few account-policy integers from
// `pwpolicy -getaccountpolicies` plist output. Best effort: missing keys
// simply stay absent.
func parsePwpolicyAccountPolicies(out string) map[string]int {
	m := map[string]int{}
	patterns := map[string]string{
		"min_chars":                `minimumLength\w*</key>\s*<integer>(\d+)</integer>`,
		"max_failed_logins":        `maxFailedLoginAttempts</key>\s*<integer>(\d+)</integer>`,
		"lockout_time":             `autoEnableInSeconds</key>\s*<integer>(\d+)</integer>`,
		"password_history":         `passwordHistoryDepth</key>\s*<integer>(\d+)</integer>`,
		"max_minutes_until_change": `maxMinutesUntilChangePassword</key>\s*<integer>(\d+)</integer>`,
	}
	for k, p := range patterns {
		if m2 := regexp.MustCompile(p).FindStringSubmatch(out); m2 != nil {
			if n, err := strconv.Atoi(m2[1]); err == nil {
				m[k] = n
			}
		}
	}
	return m
}

// ProxySettings is a parsed OS proxy configuration.
type ProxySettings struct {
	Enabled    bool
	Server     string
	Autoconfig string
	Bypass     string
}

// parseScutilProxy parses macOS `scutil --proxy` dictionary output.
func parseScutilProxy(out string) ProxySettings {
	var p ProxySettings
	exceptions := []string{}
	inExceptions := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "ExceptionsList") {
			inExceptions = strings.Contains(t, "{")
			continue
		}
		if inExceptions {
			if strings.HasPrefix(t, "}") {
				inExceptions = false
				continue
			}
			if s := strings.Trim(t, `", `); s != "" && !strings.HasPrefix(s, "<") {
				if idx := strings.Index(s, ":"); idx >= 0 {
					exceptions = append(exceptions, strings.TrimSpace(s[idx+1:]))
				}
			}
			continue
		}
		k, v, ok := cutColon(t)
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "HTTPEnable":
			p.Enabled = v == "1"
		case "HTTPProxy":
			p.Server = v
		case "HTTPPort":
			if p.Server != "" && v != "" {
				p.Server += ":" + v
			}
		case "ProxyAutoConfigURLString":
			p.Autoconfig = v
		}
	}
	p.Bypass = strings.Join(exceptions, ";")
	return p
}

// IwLink is `iw <if> link` output: current association, no scan.
type IwLink struct {
	Connected bool
	SSID      string
	BSSID     string
	SignalDbm *int
	Freq      *int
}

// parseIwLink parses `iw dev <if> link` output.
func parseIwLink(out string) IwLink {
	var l IwLink
	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return l
	}
	first := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(first, "Connected to ") {
		return l
	}
	l.Connected = true
	if f := strings.Fields(first); len(f) >= 3 {
		l.BSSID = f[2]
	}
	for _, line := range lines[1:] {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "SSID: "):
			l.SSID = strings.TrimSpace(strings.TrimPrefix(t, "SSID: "))
		case strings.HasPrefix(t, "signal: "):
			if f := strings.Fields(strings.TrimPrefix(t, "signal: ")); len(f) > 0 {
				if n, err := strconv.Atoi(f[0]); err == nil {
					l.SignalDbm = &n
				}
			}
		case strings.HasPrefix(t, "freq: "):
			if f := strings.Fields(strings.TrimPrefix(t, "freq: ")); len(f) > 0 {
				if n, err := strconv.Atoi(f[0]); err == nil {
					l.Freq = &n
				}
			}
		}
	}
	return l
}

// freqToChannel converts a Wi-Fi frequency (MHz) to a channel number.
func freqToChannel(freq int) int {
	switch {
	case freq >= 2412 && freq <= 2472:
		return (freq - 2407) / 5
	case freq == 2484:
		return 14
	case freq >= 5000 && freq <= 5900:
		return (freq - 5000) / 5
	case freq >= 5955 && freq <= 7115:
		return (freq - 5950) / 5
	default:
		return 0
	}
}

// splitCIDR splits "192.168.1.5/24" into host and dotted mask parts.
func splitCIDR(addr string) (host, mask string) {
	a := addr
	if i := strings.Index(a, "%"); i >= 0 {
		a = a[:i] // strip zone id
	}
	if !strings.Contains(a, "/") {
		return a, ""
	}
	ip, ipnet, err := net.ParseCIDR(a)
	if err != nil {
		return addr, ""
	}
	if ip.To4() == nil {
		return ip.String(), ""
	}
	return ip.String(), net.IP(ipnet.Mask).String()
}

// normalizeMAC lowercases a MAC and strips all separators for join keys.
func normalizeMAC(mac string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(mac) {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// dotnetFrameworkName maps a .NET Framework release DWORD to a version.
func dotnetFrameworkName(release int) string {
	switch {
	case release >= 533320:
		return "4.8.1"
	case release >= 528040:
		return "4.8"
	case release >= 461808:
		return "4.7.2"
	case release >= 461308:
		return "4.7.1"
	case release >= 460798:
		return "4.7"
	case release >= 394802:
		return "4.6.2"
	case release >= 394254:
		return "4.6.1"
	case release >= 393295:
		return "4.6"
	case release >= 379893:
		return "4.5.2"
	case release >= 378675:
		return "4.5.1"
	case release >= 378389:
		return "4.5"
	default:
		return ""
	}
}

// nlmCategoryName maps an NLM Category value to its assessment vocabulary.
func nlmCategoryName(id uint64) string {
	switch id {
	case 0:
		return "public"
	case 1:
		return "private"
	case 2:
		return "domain"
	default:
		return "unknown"
	}
}

// any* helpers map missing values to JSON null (or [] for arrays) so both
// implementations agree on field presence for the assessment entities.
func anyStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func anyInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func anyInt64(n int64, ok bool) any {
	if !ok {
		return nil
	}
	return n
}

func anyBool(p *bool) any {
	if p == nil {
		return nil
	}
	return *p
}

func anyStrings(v []string) any {
	if len(v) == 0 {
		return []string{}
	}
	return v
}

// nowUTC is the clock hook for assessment collectors (replaced in tests).
var nowUTC = func() time.Time { return time.Now().UTC() }

// parseISOTime parses the timestamp shapes the assessment sources emit:
// round-trip ISO-8601 first, then the space-separated WMI/registry shape.
func parseISOTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, nil
		}
	}
	return time.Time{}, strconv.ErrSyntax
}

// sshdOpt reads an sshd_config option, reporting "default" when unset.
func sshdOpt(m map[string]string, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	return "default"
}

// parseNetworksetupPorts maps "Hardware Port" names to BSD devices from
// `networksetup -listallhardwareports` output.
func parseNetworksetupPorts(out string) map[string]string {
	m := map[string]string{}
	var port string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Hardware Port:") {
			port = strings.TrimSpace(strings.TrimPrefix(t, "Hardware Port:"))
		} else if strings.HasPrefix(t, "Device:") && port != "" {
			m[port] = strings.TrimSpace(strings.TrimPrefix(t, "Device:"))
			port = ""
		}
	}
	return m
}

// AirportInfo is the parsed `airport -I` association detail.
type AirportInfo struct {
	SSID    string
	BSSID   string
	RSSI    *int
	Channel *int
	Auth    string
}

// parseAirportI parses `airport -I` output (best effort; absent on new macOS).
func parseAirportI(out string) AirportInfo {
	var a AirportInfo
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "SSID:"):
			a.SSID = strings.TrimSpace(strings.TrimPrefix(t, "SSID:"))
		case strings.HasPrefix(t, "BSSID:"):
			a.BSSID = strings.TrimSpace(strings.TrimPrefix(t, "BSSID:"))
		case strings.HasPrefix(t, "agrCtlRSSI:"):
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(t, "agrCtlRSSI:"))); err == nil {
				a.RSSI = &n
			}
		case strings.HasPrefix(t, "channel:"):
			if f := strings.Fields(strings.TrimPrefix(t, "channel:")); len(f) > 0 {
				first := strings.Split(f[0], ",")[0]
				if n, err := strconv.Atoi(first); err == nil {
					a.Channel = &n
				}
			}
		case strings.HasPrefix(t, "link auth:"):
			a.Auth = strings.TrimSpace(strings.TrimPrefix(t, "link auth:"))
		}
	}
	return a
}

// parseRouteGetDefault extracts the gateway and interface from
// `route -n get default` output.
func parseRouteGetDefault(out string) (gateway, iface string) {
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		f := strings.Fields(t)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "gateway:":
			gateway = f[1]
		case "interface:":
			iface = f[1]
		}
	}
	return gateway, iface
}

// parseDscacheutilUIDs returns names with the given uid from
// `dscacheutil -q user` output.
func parseDscacheutilUIDs(out string, wantUID string) []string {
	var names []string
	var name string
	flush := func(uid string) {
		if uid == wantUID && name != "" {
			names = append(names, name)
		}
		name = ""
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "name:") {
			name = strings.TrimSpace(strings.TrimPrefix(t, "name:"))
		} else if strings.HasPrefix(t, "uid:") {
			flush(strings.TrimSpace(strings.TrimPrefix(t, "uid:")))
		}
	}
	return names
}

// dottedVersion extracts the first dotted version token from --version output.
func dottedVersion(out string) string {
	if m := regexp.MustCompile(`\d+(?:\.\d+)+`).FindString(out); m != "" {
		return m
	}
	return ""
}

// maxDottedVersion returns the highest dot-separated numeric version.
func maxDottedVersion(vs []string) string {
	best := ""
	for _, v := range vs {
		if betterDotted(v, best) {
			best = v
		}
	}
	return best
}

func betterDotted(a, b string) bool {
	if b == "" {
		return a != ""
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		if ea != nil || eb != nil {
			if pa[i] != pb[i] {
				return pa[i] > pb[i]
			}
			continue
		}
		if na != nb {
			return na > nb
		}
	}
	return len(pa) > len(pb)
}
