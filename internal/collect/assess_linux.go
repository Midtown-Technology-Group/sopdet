//go:build linux

package collect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// enrichNetworkInterfaces adds gateway, DNS, mask, and link-speed fields to
// the base gopsutil NIC records. CIDR addresses are split into bare IPs so
// values match the Windows implementation.
func enrichNetworkInterfaces(recs []schema.Record) {
	routes := parseProcNetRoute(readTrim("/proc/net/route"))
	gwByIface := map[string][]string{}
	for _, r := range routes {
		if r.Destination == "0.0.0.0" && r.Gateway != "" && r.Gateway != "0.0.0.0" {
			gwByIface[r.Interface] = append(gwByIface[r.Interface], r.Gateway)
		}
	}
	resolv := parseResolvConf(readTrim("/etc/resolv.conf"))
	for _, rec := range recs {
		name, _ := rec["adapter_name"].(string)
		addrs, _ := rec["ip_addresses"].([]string)
		hosts := make([]string, 0, len(addrs))
		masks := []string{}
		for _, a := range addrs {
			h, m := splitCIDR(a)
			hosts = append(hosts, h)
			if m != "" {
				masks = append(masks, m)
			}
		}
		rec["ip_addresses"] = hosts
		rec["interface_index"] = nil
		rec["description"] = nil
		rec["subnet_masks"] = anyStrings(masks)
		rec["default_gateway"] = anyStrings(gwByIface[name])
		rec["dns_servers"] = anyStrings(resolv.Servers)
		rec["dns_domain"] = anyStr(resolv.Domain)
		rec["dns_host_name"] = nil
		rec["dhcp_enabled"] = nil
		rec["dhcp_server"] = nil
		rec["link_speed_bps"] = nil
		rec["status"] = nil
		rec["service_name"] = nil
		rec["interface_type"] = nil
		if s := readTrim("/sys/class/net/" + name + "/speed"); s != "" {
			if mbps, err := strconv.Atoi(s); err == nil && mbps > 0 {
				rec["link_speed_bps"] = int64(mbps) * 1000000
			}
		}
	}
}

type linuxWifiCollector struct{}

func (linuxWifiCollector) Name() string { return "wifi_networks" }
func (linuxWifiCollector) Level() int   { return levelQuick }
func (linuxWifiCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	recs := []schema.Record{}
	ifaces, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return recs, nil
	}
	for _, iface := range ifaces {
		name := iface.Name()
		if _, err := os.Stat("/sys/class/net/" + name + "/wireless"); err != nil {
			continue
		}
		link := IwLink{}
		if out, err := assessExec(ctx, "iw", "dev", name, "link"); err == nil {
			link = parseIwLink(out)
		}
		state := "disconnected"
		if link.Connected {
			state = "connected"
		}
		var channel *int
		if link.Freq != nil {
			if c := freqToChannel(*link.Freq); c > 0 {
				channel = &c
			}
		}
		recs = append(recs, schema.Record{
			"key": "wifi:" + name, "interface": name, "state": state,
			"ssid": anyStr(link.SSID), "bssid": anyStr(link.BSSID),
			"signal_percent": nil, "signal_dbm": anyInt(link.SignalDbm),
			"radio_type": nil, "authentication": nil, "cipher": nil,
			"channel": anyInt(channel),
		})
	}
	return recs, nil
}

type linuxProxyCollector struct{}

func (linuxProxyCollector) Name() string { return "proxy_config" }
func (linuxProxyCollector) Level() int   { return levelQuick }
func (linuxProxyCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return []schema.Record{}, nil
	}
	get := func(schema, key string) string {
		out, err := assessExec(ctx, "gsettings", "get", schema, key)
		if err != nil {
			return ""
		}
		return strings.Trim(strings.TrimSpace(out), "'")
	}
	mode := get("org.gnome.system.proxy", "mode")
	if mode == "" {
		return []schema.Record{}, nil
	}
	host := get("org.gnome.system.proxy.http", "host")
	port := get("org.gnome.system.proxy.http", "port")
	server := host
	if host != "" && port != "" && port != "0" {
		server = host + ":" + port
	}
	return []schema.Record{{
		"key": "proxy", "user_proxy_enabled": mode == "manual",
		"user_proxy_server": anyStr(server), "user_proxy_bypass": nil,
		"user_autoconfig_url": anyStr(get("org.gnome.system.proxy", "autoconfig-url")),
		"system_proxy_server": nil, "system_proxy_bypass": nil, "source": "gsettings",
	}}, nil
}

type linuxRouteCollector struct{}

func (linuxRouteCollector) Name() string { return "routes" }
func (linuxRouteCollector) Level() int   { return levelQuick }
func (linuxRouteCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	recs := []schema.Record{}
	for _, r := range parseProcNetRoute(string(data)) {
		metric := "-"
		if r.Metric != nil {
			metric = strconv.Itoa(*r.Metric)
		}
		recs = append(recs, schema.Record{
			"key":         "route:" + r.Destination + "/" + r.Mask + ":" + r.Gateway + ":" + r.Interface + ":" + metric,
			"destination": r.Destination, "mask": r.Mask,
			"gateway": anyStr(r.Gateway), "interface": anyStr(r.Interface),
			"metric": anyInt(r.Metric), "family": "ipv4", "persistent": false,
		})
	}
	return recs, nil
}

type linuxArpCollector struct{}

func (linuxArpCollector) Name() string { return "arp_neighbors" }
func (linuxArpCollector) Level() int   { return levelQuick }
func (linuxArpCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	recs := []schema.Record{}
	for _, n := range parseProcNetArp(string(data)) {
		recs = append(recs, schema.Record{
			"key": "arp:" + n.IP + ":" + n.Iface, "ip_address": n.IP,
			"mac_address": anyStr(n.MAC), "interface": anyStr(n.Iface),
			"neighbor_type": anyStr(n.Type), "neighbor_state": anyStr(n.State),
		})
	}
	return recs, nil
}

type linuxScheduledTaskCollector struct{}

func (linuxScheduledTaskCollector) Name() string { return "scheduled_tasks" }
func (linuxScheduledTaskCollector) Level() int   { return levelFull }
func (linuxScheduledTaskCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	recs := []schema.Record{}
	n := 0
	addCron := func(file string, entries []CronEntry) {
		for _, e := range entries {
			n++
			user := e.User
			if user == "" {
				user = "root"
			}
			recs = append(recs, schema.Record{
				"key":       "task:cron:" + filepath.Base(file) + ":" + strconv.Itoa(n),
				"task_name": file + ":" + strconv.Itoa(e.LineNo), "status": "scheduled",
				"enabled": nil, "schedule": e.Schedule, "command": e.Command,
				"author": nil, "run_as_user": user, "logon_mode": nil,
				"last_run_time": nil, "last_result": nil, "next_run_time": nil,
				"source": "cron",
			})
		}
	}
	if data, err := os.ReadFile("/etc/crontab"); err == nil {
		addCron("/etc/crontab", parseCrontabFile(string(data), true))
	}
	if dirs, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, d := range dirs {
			if d.IsDir() {
				continue
			}
			p := "/etc/cron.d/" + d.Name()
			if data, err := os.ReadFile(p); err == nil {
				addCron(p, parseCrontabFile(string(data), true))
			}
		}
	}
	for dir, sched := range map[string]string{
		"/etc/cron.hourly": "@hourly", "/etc/cron.daily": "@daily",
		"/etc/cron.weekly": "@weekly", "/etc/cron.monthly": "@monthly",
	} {
		if dirs, err := os.ReadDir(dir); err == nil {
			for _, d := range dirs {
				if d.IsDir() || strings.HasPrefix(d.Name(), ".") {
					continue
				}
				n++
				recs = append(recs, schema.Record{
					"key":       "task:cron:" + filepath.Base(dir) + ":" + strconv.Itoa(n),
					"task_name": dir + "/" + d.Name(), "status": "scheduled",
					"enabled": nil, "schedule": sched, "command": dir + "/" + d.Name(),
					"author": nil, "run_as_user": "root", "logon_mode": nil,
					"last_run_time": nil, "last_result": nil, "next_run_time": nil,
					"source": "cron",
				})
			}
		}
	}
	if out, err := assessExec(ctx, "systemctl", "list-timers", "--all", "--no-pager"); err == nil {
		for _, t := range parseSystemctlTimers(out) {
			recs = append(recs, schema.Record{
				"key": "task:timer:" + t.Unit, "task_name": t.Unit, "status": "active",
				"enabled": nil, "schedule": anyStr(t.Next), "command": anyStr(t.Activates),
				"author": nil, "run_as_user": nil, "logon_mode": nil,
				"last_run_time": anyStr(t.Last), "last_result": nil,
				"next_run_time": anyStr(t.Next), "source": "systemd-timer",
			})
		}
	}
	return recs, nil
}

type linuxRemoteAccessCollector struct{}

func (linuxRemoteAccessCollector) Name() string { return "remote_access" }
func (linuxRemoteAccessCollector) Level() int   { return levelQuick }
func (linuxRemoteAccessCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	rec := schema.Record{
		"key": "remote_access", "rdp_enabled": nil, "rdp_port": nil,
		"rdp_nla_required": nil, "smb1_server": nil, "smb1_client": nil,
		"llmnr_enabled": nil, "netbios_mode": nil, "winrm_running": nil,
		"winrm_start_mode": nil, "sshd_installed": false,
		"sshd_permit_root_login": nil, "sshd_password_auth": nil,
		"sshd_port": nil, "source": "sshd-config",
	}
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		if _, err := exec.LookPath("sshd"); err != nil {
			return []schema.Record{rec}, nil
		}
		rec["sshd_installed"] = true
		return []schema.Record{rec}, nil
	}
	rec["sshd_installed"] = true
	m := parseSshdConfig(string(data))
	rec["sshd_permit_root_login"] = sshdOpt(m, "permitrootlogin")
	rec["sshd_password_auth"] = sshdOpt(m, "passwordauthentication")
	if p, ok := m["port"]; ok {
		if n, err := strconv.Atoi(p); err == nil {
			rec["sshd_port"] = n
		}
	}
	return []schema.Record{rec}, nil
}

type linuxPrivilegedMemberCollector struct{}

func (linuxPrivilegedMemberCollector) Name() string { return "privileged_members" }
func (linuxPrivilegedMemberCollector) Level() int   { return levelQuick }
func (linuxPrivilegedMemberCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	recs := []schema.Record{}
	if data, err := os.ReadFile("/etc/group"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) < 4 {
				continue
			}
			group := parts[0]
			switch group {
			case "sudo", "wheel", "admin", "docker":
			default:
				continue
			}
			for _, member := range strings.Split(parts[3], ",") {
				member = strings.TrimSpace(member)
				if member == "" {
					continue
				}
				recs = append(recs, schema.Record{
					"key": "member:" + strings.ToLower(member), "name": member,
					"domain": nil, "member_type": "user", "source": group,
				})
			}
		}
	}
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) < 3 || parts[2] != "0" || parts[0] == "root" {
				continue
			}
			recs = append(recs, schema.Record{
				"key": "member:" + strings.ToLower(parts[0]), "name": parts[0],
				"domain": nil, "member_type": "user", "source": "uid0",
			})
		}
	}
	return recs, nil
}

type linuxPasswordPolicyCollector struct{}

func (linuxPasswordPolicyCollector) Name() string { return "password_policy" }
func (linuxPasswordPolicyCollector) Level() int   { return levelQuick }
func (linuxPasswordPolicyCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	rec := schema.Record{
		"key": "password_policy", "max_password_age_days": nil,
		"min_password_age_days": nil, "min_password_length": nil,
		"password_history": nil, "lockout_threshold": nil,
		"lockout_duration_minutes": nil, "lockout_reset_minutes": nil,
		"source": "login.defs",
	}
	data, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return []schema.Record{rec}, nil
	}
	m := parseLoginDefs(string(data))
	setDef := func(field, key string) {
		if v, ok := m[key]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				rec[field] = n
			}
		}
	}
	setDef("max_password_age_days", "PASS_MAX_DAYS")
	setDef("min_password_age_days", "PASS_MIN_DAYS")
	setDef("min_password_length", "PASS_MIN_LEN")
	return []schema.Record{rec}, nil
}

type linuxUpdateHealthCollector struct{}

func (linuxUpdateHealthCollector) Name() string { return "update_health" }
func (linuxUpdateHealthCollector) Level() int   { return levelQuick }
func (linuxUpdateHealthCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	rec := schema.Record{
		"key": "update_health", "last_success_time": nil, "update_source": nil,
		"wsus_server": nil, "auto_update_option": nil, "auto_updates": nil,
		"pending_reboot": false, "pending_reboot_reasons": []string{},
		"source": "package-logs",
	}
	logs := []struct {
		path   string
		source string
	}{
		{"/var/log/dpkg.log", "apt"},
		{"/var/log/apt/history.log", "apt"},
		{"/var/log/dnf.rpm.log", "dnf"},
		{"/var/log/yum.log", "yum"},
		{"/var/log/pacman.log", "pacman"},
	}
	var latest time.Time
	for _, l := range logs {
		st, err := os.Stat(l.path)
		if err != nil {
			continue
		}
		if st.ModTime().After(latest) {
			latest = st.ModTime()
			rec["update_source"] = l.source
		}
	}
	if !latest.IsZero() {
		rec["last_success_time"] = latest.UTC().Format("2006-01-02T15:04:05Z")
	}
	if data, err := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		s := strings.ReplaceAll(string(data), " ", "")
		if strings.Contains(s, `Unattended-Upgrade"1"`) || strings.Contains(s, "Unattended-Upgrade'1'") {
			rec["auto_updates"] = true
		} else if strings.Contains(s, "Unattended-Upgrade") {
			rec["auto_updates"] = false
		}
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		rec["pending_reboot"] = true
		rec["pending_reboot_reasons"] = []string{"packages"}
	}
	return []schema.Record{rec}, nil
}

type linuxReliabilityCollector struct{}

func (linuxReliabilityCollector) Name() string { return "reliability" }
func (linuxReliabilityCollector) Level() int   { return levelFull }
func (linuxReliabilityCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	rec := schema.Record{
		"key": "reliability", "unexpected_shutdowns": 0, "kernel_power_events": nil,
		"bugchecks": nil, "clean_shutdowns": 0, "last_unexpected_shutdown": nil,
		"last_bugcheck": nil, "source": "wtmp",
	}
	out, err := assessExec(ctx, "last", "-x", "reboot", "shutdown")
	if err != nil {
		return []schema.Record{rec}, nil
	}
	s := parseLastWTMP(out, nowUTC().Year())
	rec["unexpected_shutdowns"] = s.Crashes
	rec["clean_shutdowns"] = s.Shutdowns
	rec["last_unexpected_shutdown"] = anyStr(s.LastCrash)
	return []schema.Record{rec}, nil
}

type linuxRuntimeCollector struct{}

func (linuxRuntimeCollector) Name() string { return "runtimes" }
func (linuxRuntimeCollector) Level() int   { return levelQuick }
func (linuxRuntimeCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	recs := []schema.Record{}
	interp := []struct {
		name string
		slug string
		bin  string
		args []string
	}{
		{"Python 3", "python3", "python3", []string{"--version"}},
		{"PowerShell", "pwsh", "pwsh", []string{"--version"}},
	}
	for _, in := range interp {
		if _, err := exec.LookPath(in.bin); err != nil {
			continue
		}
		out, err := assessExec(ctx, in.bin, in.args...)
		if err != nil {
			continue
		}
		if v := dottedVersion(out); v != "" {
			recs = append(recs, schema.Record{
				"key": "runtime:interpreter:" + in.slug + ":" + v, "kind": "interpreter",
				"name": in.name, "version": v, "path": nil,
				"machine_policy": nil, "user_policy": nil, "source": "exec",
			})
		}
	}
	browsers := []struct {
		name string
		slug string
		bin  string
	}{
		{"Google Chrome", "chrome", "google-chrome"},
		{"Chromium", "chromium", "chromium"},
		{"Mozilla Firefox", "firefox", "firefox"},
	}
	for _, b := range browsers {
		if _, err := exec.LookPath(b.bin); err != nil {
			continue
		}
		out, err := assessExec(ctx, b.bin, "--version")
		if err != nil {
			continue
		}
		if v := dottedVersion(out); v != "" {
			recs = append(recs, schema.Record{
				"key": "runtime:browser:" + b.slug + ":" + v, "kind": "browser",
				"name": b.name, "version": v, "path": nil,
				"machine_policy": nil, "user_policy": nil, "source": "exec",
			})
		}
	}
	if out, err := assessExec(ctx, "dotnet", "--list-runtimes"); err == nil {
		for _, r := range parseDotnetRuntimes(out) {
			recs = append(recs, schema.Record{
				"key": "runtime:dotnet:" + r.Name + ":" + r.Version, "kind": "dotnet",
				"name": r.Name, "version": r.Version, "path": anyStr(r.Path),
				"machine_policy": nil, "user_policy": nil, "source": "dotnet-cli",
			})
		}
	}
	return recs, nil
}
