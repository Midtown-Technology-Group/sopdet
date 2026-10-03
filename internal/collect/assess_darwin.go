//go:build darwin

package collect

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// enrichNetworkInterfaces adds gateway, DNS, and mask fields to the base
// gopsutil NIC records. CIDR addresses are split into bare IPs so values
// match the other implementations.
func enrichNetworkInterfaces(recs []schema.Record) {
	gw, gwIface := "", ""
	if out, err := assessExec(context.Background(), "route", "-n", "get", "default"); err == nil {
		gw, gwIface = parseRouteGetDefault(out)
	}
	var resolv ResolvConf
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		resolv = parseResolvConf(string(data))
	}
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
		rec["default_gateway"] = []string{}
		if name == gwIface && gw != "" {
			rec["default_gateway"] = []string{gw}
		}
		rec["dns_servers"] = anyStrings(resolv.Servers)
		rec["dns_domain"] = anyStr(resolv.Domain)
		rec["dns_host_name"] = nil
		rec["dhcp_enabled"] = nil
		rec["dhcp_server"] = nil
		rec["link_speed_bps"] = nil
		rec["status"] = nil
		rec["service_name"] = nil
		rec["interface_type"] = nil
	}
}

type macWifiCollector struct{}

func (macWifiCollector) Name() string { return "wifi_networks" }
func (macWifiCollector) Level() int   { return levelQuick }
func (macWifiCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "networksetup", "-listallhardwareports")
	if err != nil {
		return []schema.Record{}, nil
	}
	dev := parseNetworksetupPorts(out)["Wi-Fi"]
	if dev == "" {
		return []schema.Record{}, nil
	}
	rec := schema.Record{
		"key": "wifi:" + dev, "interface": dev, "state": "disconnected",
		"ssid": nil, "bssid": nil, "signal_percent": nil, "signal_dbm": nil,
		"radio_type": nil, "authentication": nil, "cipher": nil, "channel": nil,
	}
	if out, err := assessExec(ctx, "networksetup", "-getairportnetwork", dev); err == nil {
		if strings.Contains(out, "Current Wi-Fi Network:") {
			rec["state"] = "connected"
			rec["ssid"] = anyStr(strings.TrimSpace(strings.SplitN(out, ":", 2)[1]))
		}
	}
	const airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
	if out, err := assessExec(ctx, airport, "-I"); err == nil {
		a := parseAirportI(out)
		if a.SSID != "" {
			rec["state"] = "connected"
			rec["ssid"] = a.SSID
		}
		rec["bssid"] = anyStr(a.BSSID)
		rec["signal_dbm"] = anyInt(a.RSSI)
		rec["channel"] = anyInt(a.Channel)
		rec["authentication"] = anyStr(a.Auth)
	}
	return []schema.Record{rec}, nil
}

type macProxyCollector struct{}

func (macProxyCollector) Name() string { return "proxy_config" }
func (macProxyCollector) Level() int   { return levelQuick }
func (macProxyCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "scutil", "--proxy")
	if err != nil {
		return []schema.Record{}, nil
	}
	p := parseScutilProxy(out)
	return []schema.Record{{
		"key": "proxy", "user_proxy_enabled": nil, "user_proxy_server": nil,
		"user_proxy_bypass": nil, "user_autoconfig_url": anyStr(p.Autoconfig),
		"system_proxy_server": anyStr(p.Server), "system_proxy_bypass": anyStr(p.Bypass),
		"source": "scutil",
	}}, nil
}

type macRouteCollector struct{}

func (macRouteCollector) Name() string { return "routes" }
func (macRouteCollector) Level() int   { return levelQuick }
func (macRouteCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}
	recs := []schema.Record{}
	for _, r := range parseNetstatInetRoutes(out) {
		metric := "-"
		if r.Metric != nil {
			metric = strconv.Itoa(*r.Metric)
		}
		recs = append(recs, schema.Record{
			"key":         "route:" + r.Destination + "/" + r.Mask + ":" + r.Gateway + ":" + r.Interface + ":" + metric,
			"destination": r.Destination, "mask": anyStr(r.Mask),
			"gateway": anyStr(r.Gateway), "interface": anyStr(r.Interface),
			"metric": anyInt(r.Metric), "family": "ipv4", "persistent": false,
		})
	}
	return recs, nil
}

type macArpCollector struct{}

func (macArpCollector) Name() string { return "arp_neighbors" }
func (macArpCollector) Level() int   { return levelQuick }
func (macArpCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "arp", "-a")
	if err != nil {
		return nil, err
	}
	recs := []schema.Record{}
	for _, n := range parseArpADarwin(out) {
		recs = append(recs, schema.Record{
			"key": "arp:" + n.IP + ":" + n.Iface, "ip_address": n.IP,
			"mac_address": anyStr(n.MAC), "interface": anyStr(n.Iface),
			"neighbor_type": anyStr(n.Type), "neighbor_state": nil,
		})
	}
	return recs, nil
}

type macScheduledTaskCollector struct{}

func (macScheduledTaskCollector) Name() string { return "scheduled_tasks" }
func (macScheduledTaskCollector) Level() int   { return levelFull }
func (macScheduledTaskCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	recs := []schema.Record{}
	loaded := map[string]bool{}
	if out, err := assessExec(ctx, "launchctl", "list"); err == nil {
		for _, j := range parseLaunchctlList(out) {
			loaded[j.Label] = true
			status := "loaded"
			if j.PID != "" && j.PID != "-" {
				status = "running"
			} else if j.Status != "0" {
				status = "exit-" + j.Status
			}
			recs = append(recs, schema.Record{
				"key": "task:launchd:" + j.Label, "task_name": j.Label,
				"status": status, "enabled": nil, "schedule": nil, "command": nil,
				"author": nil, "run_as_user": nil, "logon_mode": nil,
				"last_run_time": nil, "last_result": anyStr(j.Status),
				"next_run_time": nil, "source": "launchd",
			})
		}
	}
	for _, dir := range []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			label := strings.TrimSuffix(e.Name(), ".plist")
			if loaded[label] {
				continue
			}
			recs = append(recs, schema.Record{
				"key": "task:launchd-file:" + label, "task_name": dir + "/" + e.Name(),
				"status": "on-disk", "enabled": nil, "schedule": nil,
				"command": nil, "author": nil, "run_as_user": nil, "logon_mode": nil,
				"last_run_time": nil, "last_result": nil, "next_run_time": nil,
				"source": "launchd",
			})
		}
	}
	return recs, nil
}

type macRemoteAccessCollector struct{}

func (macRemoteAccessCollector) Name() string { return "remote_access" }
func (macRemoteAccessCollector) Level() int   { return levelQuick }
func (macRemoteAccessCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
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

type macPrivilegedMemberCollector struct{}

func (macPrivilegedMemberCollector) Name() string { return "privileged_members" }
func (macPrivilegedMemberCollector) Level() int   { return levelQuick }
func (macPrivilegedMemberCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	recs := []schema.Record{}
	if data, err := os.ReadFile("/etc/group"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) < 4 {
				continue
			}
			switch parts[0] {
			case "admin", "wheel":
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
					"domain": nil, "member_type": "user", "source": parts[0],
				})
			}
		}
	}
	if out, err := assessExec(ctx, "dscacheutil", "-q", "user"); err == nil {
		for _, name := range parseDscacheutilUIDs(out, "0") {
			if name == "root" {
				continue
			}
			recs = append(recs, schema.Record{
				"key": "member:" + strings.ToLower(name), "name": name,
				"domain": nil, "member_type": "user", "source": "uid0",
			})
		}
	}
	return recs, nil
}

type macPasswordPolicyCollector struct{}

func (macPasswordPolicyCollector) Name() string { return "password_policy" }
func (macPasswordPolicyCollector) Level() int   { return levelQuick }
func (macPasswordPolicyCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	rec := schema.Record{
		"key": "password_policy", "max_password_age_days": nil,
		"min_password_age_days": nil, "min_password_length": nil,
		"password_history": nil, "lockout_threshold": nil,
		"lockout_duration_minutes": nil, "lockout_reset_minutes": nil,
		"source": "pwpolicy",
	}
	out, err := assessExec(ctx, "pwpolicy", "-getaccountpolicies")
	if err != nil {
		return []schema.Record{rec}, nil
	}
	m := parsePwpolicyAccountPolicies(out)
	if v, ok := m["min_chars"]; ok {
		rec["min_password_length"] = v
	}
	if v, ok := m["max_failed_logins"]; ok {
		rec["lockout_threshold"] = v
	}
	if v, ok := m["lockout_time"]; ok {
		rec["lockout_reset_minutes"] = v / 60
	}
	if v, ok := m["password_history"]; ok {
		rec["password_history"] = v
	}
	if v, ok := m["max_minutes_until_change"]; ok {
		rec["max_password_age_days"] = v / 1440
	}
	return []schema.Record{rec}, nil
}

type macUpdateHealthCollector struct{}

func (macUpdateHealthCollector) Name() string { return "update_health" }
func (macUpdateHealthCollector) Level() int   { return levelQuick }
func (macUpdateHealthCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	rec := schema.Record{
		"key": "update_health", "last_success_time": nil, "update_source": "softwareupdate",
		"wsus_server": nil, "auto_update_option": nil, "auto_updates": nil,
		"pending_reboot": nil, "pending_reboot_reasons": []string{},
		"source": "softwareupdate",
	}
	if data, err := os.ReadFile("/Library/Receipts/InstallHistory.plist"); err == nil {
		if latest, _ := parseMacInstallHistory(string(data)); latest != "" {
			rec["last_success_time"] = latest
		}
	}
	out, err := assessExec(ctx, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheck")
	if err == nil {
		rec["auto_updates"] = strings.TrimSpace(out) == "1"
	}
	return []schema.Record{rec}, nil
}

type macReliabilityCollector struct{}

func (macReliabilityCollector) Name() string { return "reliability" }
func (macReliabilityCollector) Level() int   { return levelFull }
func (macReliabilityCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	rec := schema.Record{
		"key": "reliability", "unexpected_shutdowns": 0, "kernel_power_events": nil,
		"bugchecks": nil, "clean_shutdowns": 0, "last_unexpected_shutdown": nil,
		"last_bugcheck": nil, "source": "wtmp",
	}
	out, err := assessExec(ctx, "last", "reboot", "shutdown")
	if err != nil {
		return []schema.Record{rec}, nil
	}
	s := parseLastWTMP(out, nowUTC().Year())
	rec["unexpected_shutdowns"] = s.Crashes
	rec["clean_shutdowns"] = s.Shutdowns
	rec["last_unexpected_shutdown"] = anyStr(s.LastCrash)
	return []schema.Record{rec}, nil
}

type macRuntimeCollector struct{}

func (macRuntimeCollector) Name() string { return "runtimes" }
func (macRuntimeCollector) Level() int   { return levelQuick }
func (macRuntimeCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	recs := []schema.Record{}
	if _, err := exec.LookPath("python3"); err == nil {
		if out, err := assessExec(ctx, "python3", "--version"); err == nil {
			if v := dottedVersion(out); v != "" {
				recs = append(recs, schema.Record{
					"key": "runtime:interpreter:python3:" + v, "kind": "interpreter",
					"name": "Python 3", "version": v, "path": nil,
					"machine_policy": nil, "user_policy": nil, "source": "exec",
				})
			}
		}
	}
	if out, err := assessExec(ctx, "defaults", "read", "/Applications/Safari.app/Contents/Info", "CFBundleShortVersionString"); err == nil {
		if v := strings.TrimSpace(out); v != "" {
			recs = append(recs, schema.Record{
				"key": "runtime:browser:safari:" + v, "kind": "browser",
				"name": "Safari", "version": v, "path": nil,
				"machine_policy": nil, "user_policy": nil, "source": "exec",
			})
		}
	}
	for _, b := range []struct{ name, slug, bin string }{
		{"Google Chrome", "chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
		{"Mozilla Firefox", "firefox", "/Applications/Firefox.app/Contents/MacOS/firefox"},
	} {
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
