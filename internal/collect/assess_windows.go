//go:build windows

package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

// decodePSRows decodes a PowerShell ConvertTo-Json payload that may be an
// array, a single object, or empty.
func decodePSRows[T any](out string) ([]T, error) {
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	var rows []T
	if err := json.Unmarshal([]byte(out), &rows); err == nil {
		return rows, nil
	}
	var single T
	if err := json.Unmarshal([]byte(out), &single); err != nil {
		return nil, err
	}
	return []T{single}, nil
}

// wmiQueryRetry runs a WMI query once, retrying a single time after a short
// pause. Bulk queries flake occasionally under load; callers treat a final
// failure as missing data, never fatal.
func wmiQueryRetry(query string, dst any) error {
	if err := wmi.Query(query, dst); err == nil {
		return nil
	}
	time.Sleep(2 * time.Second)
	return wmi.Query(query, dst)
}

// Registry helpers. Reads use the 64-bit view so results do not depend on
// the collector process architecture.

func regString(root registry.Key, path, name string) (string, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return "", false
	}
	return v, true
}

func regDWORD(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return v, true
}

func regKeyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func regSubKeys(root registry.Key, path string) []string {
	k, err := registry.OpenKey(root, path, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	return names
}

func regStrings(root registry.Key, path, name string) ([]string, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, false
	}
	defer k.Close()
	v, _, err := k.GetStringsValue(name)
	if err != nil {
		return nil, false
	}
	return v, true
}

// enrichNetworkInterfaces joins WMI adapter/configuration rows onto the base
// gopsutil NIC records by MAC address. It never fails: on any error the
// records keep their base fields with explicit nulls so field presence
// matches the PowerShell implementation.
func enrichNetworkInterfaces(recs []schema.Record) {
	type adapter struct {
		Index               uint32
		NetConnectionID     string
		Description         string
		MACAddress          string
		Speed               uint64
		NetConnectionStatus uint32
	}
	type config struct {
		Index                uint32
		IPEnabled            bool
		IPAddress            []string
		IPSubnet             []string
		DefaultIPGateway     []string
		DNSServerSearchOrder []string
		DNSDomain            string
		DNSHostName          string
		DHCPEnabled          bool
		DHCPServer           string
		ServiceName          string
	}
	var adapters []adapter
	var configs []config
	// One retry each: CI showed these bulk queries can flake once under
	// load while per-NIC queries succeed. Config rows are IPEnabled-only
	// (matching the PowerShell collector), which also skips the
	// NULL-laden rows of down/virtual adapters.
	if err := wmiQueryRetry("SELECT Index,NetConnectionID,Description,MACAddress,Speed,NetConnectionStatus FROM Win32_NetworkAdapter", &adapters); err != nil {
		adapters = nil
	}
	if err := wmiQueryRetry("SELECT Index,IPEnabled,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder,DNSDomain,DNSHostName,DHCPEnabled,DHCPServer,ServiceName FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE", &configs); err != nil {
		configs = nil
	}
	byIndex := map[uint32]config{}
	for _, c := range configs {
		byIndex[c.Index] = c
	}
	byMAC := map[string]struct {
		a  adapter
		c  config
		ok bool
	}{}
	for _, a := range adapters {
		nm := normalizeMAC(a.MACAddress)
		if nm == "" {
			continue
		}
		c, ok := byIndex[a.Index]
		// Prefer the config-having adapter when MACs collide (teamed or
		// virtual adapters share MACs and WMI row order is not stable).
		if e, taken := byMAC[nm]; taken && (e.ok || !ok) {
			continue
		}
		byMAC[nm] = struct {
			a  adapter
			c  config
			ok bool
		}{a, c, ok}
	}
	for _, rec := range recs {
		mac, _ := rec["mac_address"].(string)
		rec["interface_index"] = nil
		rec["description"] = nil
		rec["subnet_masks"] = []string{}
		rec["default_gateway"] = []string{}
		rec["dns_servers"] = []string{}
		rec["dns_domain"] = nil
		rec["dns_host_name"] = nil
		rec["dhcp_enabled"] = nil
		rec["dhcp_server"] = nil
		rec["link_speed_bps"] = nil
		rec["status"] = nil
		rec["service_name"] = nil
		rec["interface_type"] = nil
		joined, ok := byMAC[normalizeMAC(mac)]
		if !ok {
			continue
		}
		rec["interface_index"] = int64(joined.a.Index)
		rec["adapter_name"] = joined.a.Description
		rec["description"] = anyStr(joined.a.Description)
		if joined.a.Speed > 0 {
			rec["link_speed_bps"] = int64(joined.a.Speed)
		}
		rec["status"] = int64(joined.a.NetConnectionStatus)
		if !joined.ok || !joined.c.IPEnabled {
			continue
		}
		rec["subnet_masks"] = anyStrings(joined.c.IPSubnet)
		rec["default_gateway"] = anyStrings(joined.c.DefaultIPGateway)
		rec["dns_servers"] = anyStrings(joined.c.DNSServerSearchOrder)
		rec["dns_domain"] = anyStr(joined.c.DNSDomain)
		rec["dns_host_name"] = anyStr(joined.c.DNSHostName)
		rec["dhcp_enabled"] = joined.c.DHCPEnabled
		rec["dhcp_server"] = anyStr(joined.c.DHCPServer)
		rec["service_name"] = anyStr(joined.c.ServiceName)
	}
}

type winNetworkProfileCollector struct{}

func (winNetworkProfileCollector) Name() string { return "network_profiles" }
func (winNetworkProfileCollector) Level() int   { return levelQuick }
func (winNetworkProfileCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	const base = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`
	out := []schema.Record{}
	for _, id := range regSubKeys(registry.LOCAL_MACHINE, base) {
		p := base + `\` + id
		name, _ := regString(registry.LOCAL_MACHINE, p, "ProfileName")
		desc, _ := regString(registry.LOCAL_MACHINE, p, "Description")
		cat, catOK := regDWORD(registry.LOCAL_MACHINE, p, "Category")
		managed, managedOK := regDWORD(registry.LOCAL_MACHINE, p, "Managed")
		rec := schema.Record{
			"key":          "netprofile:" + id,
			"profile_name": anyStr(name),
			"description":  anyStr(desc),
			"category":     nil,
			"category_id":  nil,
			"managed":      nil,
		}
		if catOK {
			rec["category_id"] = int64(cat)
			rec["category"] = nlmCategoryName(cat)
		}
		if managedOK {
			rec["managed"] = managed != 0
		}
		out = append(out, rec)
	}
	return out, nil
}

type winWifiCollector struct{}

func (winWifiCollector) Name() string { return "wifi_networks" }
func (winWifiCollector) Level() int   { return levelQuick }
func (winWifiCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "netsh", "wlan", "show", "interfaces")
	if err != nil {
		return []schema.Record{}, nil
	}
	recs := []schema.Record{}
	for _, w := range parseNetshWLANInterfaces(out) {
		recs = append(recs, schema.Record{
			"key":            "wifi:" + w.Interface,
			"interface":      w.Interface,
			"state":          anyStr(w.State),
			"ssid":           anyStr(w.SSID),
			"bssid":          anyStr(w.BSSID),
			"signal_percent": anyInt(w.SignalPercent),
			"signal_dbm":     nil,
			"radio_type":     anyStr(w.RadioType),
			"authentication": anyStr(w.Authentication),
			"cipher":         anyStr(w.Cipher),
			"channel":        anyInt(w.Channel),
		})
	}
	return recs, nil
}

type winProxyCollector struct{}

func (winProxyCollector) Name() string { return "proxy_config" }
func (winProxyCollector) Level() int   { return levelQuick }
func (winProxyCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	const userPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	enabled, enabledOK := regDWORD(registry.CURRENT_USER, userPath, "ProxyEnable")
	server, _ := regString(registry.CURRENT_USER, userPath, "ProxyServer")
	bypass, _ := regString(registry.CURRENT_USER, userPath, "ProxyOverride")
	autocfg, _ := regString(registry.CURRENT_USER, userPath, "AutoConfigURL")
	rec := schema.Record{
		"key":                 "proxy",
		"user_proxy_enabled":  nil,
		"user_proxy_server":   anyStr(server),
		"user_proxy_bypass":   anyStr(bypass),
		"user_autoconfig_url": anyStr(autocfg),
		"system_proxy_server": nil,
		"system_proxy_bypass": nil,
		"source":              "registry+netsh",
	}
	if enabledOK {
		rec["user_proxy_enabled"] = enabled != 0
	}
	if out, err := assessExec(ctx, "netsh", "winhttp", "show", "proxy"); err == nil {
		p := parseNetshWinhttpProxy(out)
		if !p.Direct {
			rec["system_proxy_server"] = anyStr(p.Server)
			rec["system_proxy_bypass"] = anyStr(p.Bypass)
		}
	}
	return []schema.Record{rec}, nil
}

type winRouteCollector struct{}

func (winRouteCollector) Name() string { return "routes" }
func (winRouteCollector) Level() int   { return levelQuick }
func (winRouteCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "route", "print", "-4")
	if err != nil {
		// Mirror the PowerShell collector: a failed helper yields no
		// records rather than an entity error.
		return []schema.Record{}, nil
	}
	recs := []schema.Record{}
	for _, r := range parseRoutePrint4(out) {
		metric := "-"
		if r.Metric != nil {
			metric = strconv.Itoa(*r.Metric)
		}
		key := fmt.Sprintf("route:%s/%s:%s:%s:%s", r.Destination, r.Mask, r.Gateway, r.Interface, metric)
		if r.Persistent {
			key += ":P"
		}
		recs = append(recs, schema.Record{
			"key":         key,
			"destination": r.Destination,
			"mask":        r.Mask,
			"gateway":     anyStr(r.Gateway),
			"interface":   anyStr(r.Interface),
			"metric":      anyInt(r.Metric),
			"family":      "ipv4",
			"persistent":  r.Persistent,
		})
	}
	return recs, nil
}

type winArpCollector struct{}

func (winArpCollector) Name() string { return "arp_neighbors" }
func (winArpCollector) Level() int   { return levelQuick }
func (winArpCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "arp", "-a")
	if err != nil {
		// Mirror the PowerShell collector: a failed helper yields no
		// records rather than an entity error.
		return []schema.Record{}, nil
	}
	recs := []schema.Record{}
	for _, n := range parseArpAWindows(out) {
		recs = append(recs, schema.Record{
			"key":            "arp:" + n.IP + ":" + n.Iface,
			"ip_address":     n.IP,
			"mac_address":    anyStr(n.MAC),
			"interface":      anyStr(n.Iface),
			"neighbor_type":  anyStr(n.Type),
			"neighbor_state": nil,
		})
	}
	return recs, nil
}

type winScheduledTaskCollector struct{}

func (winScheduledTaskCollector) Name() string { return "scheduled_tasks" }
func (winScheduledTaskCollector) Level() int   { return levelFull }
func (winScheduledTaskCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "schtasks", "/query", "/fo", "csv", "/v")
	if err != nil {
		// Mirror the PowerShell collector: a failed helper yields no
		// records rather than an entity error.
		return []schema.Record{}, nil
	}
	recs := []schema.Record{}
	for _, t := range parseSchtasksCSV(out) {
		recs = append(recs, schema.Record{
			"key":           "task:" + t.TaskName,
			"task_name":     t.TaskName,
			"status":        anyStr(t.Status),
			"enabled":       anyBool(t.Enabled),
			"schedule":      anyStr(joinNonEmpty(t.ScheduleTyp, t.Schedule)),
			"command":       anyStr(t.Command),
			"author":        anyStr(t.Author),
			"run_as_user":   anyStr(t.RunAsUser),
			"logon_mode":    anyStr(t.LogonMode),
			"last_run_time": anyStr(t.LastRun),
			"last_result":   anyStr(t.LastResult),
			"next_run_time": anyStr(t.NextRun),
			"source":        "schtasks",
		})
	}
	return recs, nil
}

func joinNonEmpty(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + " " + b
}

type winRemoteAccessCollector struct{}

func (winRemoteAccessCollector) Name() string { return "remote_access" }
func (winRemoteAccessCollector) Level() int   { return levelQuick }
func (winRemoteAccessCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	const tsPath = `SYSTEM\CurrentControlSet\Control\Terminal Server`
	rec := schema.Record{
		"key": "remote_access", "rdp_enabled": nil, "rdp_port": nil,
		"rdp_nla_required": nil, "smb1_server": nil, "smb1_client": nil,
		"llmnr_enabled": nil, "netbios_mode": nil, "winrm_running": nil,
		"winrm_start_mode": nil, "sshd_installed": nil,
		"sshd_permit_root_login": nil, "sshd_password_auth": nil,
		"sshd_port": nil, "source": "registry+wmi",
	}
	if deny, ok := regDWORD(registry.LOCAL_MACHINE, tsPath, "fDenyTSConnections"); ok {
		rec["rdp_enabled"] = deny == 0
	}
	if port, ok := regDWORD(registry.LOCAL_MACHINE, tsPath+`\WinStations\RDP-Tcp`, "PortNumber"); ok {
		rec["rdp_port"] = int64(port)
	} else {
		rec["rdp_port"] = int64(3389)
	}
	if ua, ok := regDWORD(registry.LOCAL_MACHINE, tsPath+`\WinStations\RDP-Tcp`, "UserAuthentication"); ok {
		rec["rdp_nla_required"] = ua != 0
	}
	if smb1, ok := regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1"); ok {
		rec["smb1_server"] = smb1 != 0
	}
	if start, ok := regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\mrxsmb10`, "Start"); ok {
		rec["smb1_client"] = start != 4
	}
	if mc, ok := regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast"); ok {
		rec["llmnr_enabled"] = mc != 0
	}
	rec["netbios_mode"] = anyStr(netbiosMode())
	var svc []struct {
		State     string
		StartMode string
	}
	if err := wmi.Query("SELECT State,StartMode FROM Win32_Service WHERE Name='WinRM'", &svc); err == nil && len(svc) > 0 {
		rec["winrm_running"] = strings.EqualFold(svc[0].State, "Running")
		rec["winrm_start_mode"] = anyStr(svc[0].StartMode)
	}
	return []schema.Record{rec}, nil
}

// netbiosMode summarizes TcpipNetbiosOptions across NICs: default (DHCP),
// enabled, disabled, mixed, or empty when unreadable.
func netbiosMode() string {
	const base = `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`
	seen := map[uint64]bool{}
	for _, nic := range regSubKeys(registry.LOCAL_MACHINE, base) {
		if v, ok := regDWORD(registry.LOCAL_MACHINE, base+`\`+nic, "NetbiosOptions"); ok {
			seen[v] = true
		}
	}
	if len(seen) == 0 {
		return ""
	}
	if len(seen) > 1 {
		return "mixed"
	}
	for v := range seen {
		switch v {
		case 0:
			return "default"
		case 1:
			return "enabled"
		case 2:
			return "disabled"
		}
	}
	return "unknown"
}

type winPrivilegedMemberCollector struct{}

func (winPrivilegedMemberCollector) Name() string { return "privileged_members" }
func (winPrivilegedMemberCollector) Level() int   { return levelQuick }
func (winPrivilegedMemberCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "net", "localgroup", "administrators")
	if err != nil {
		// Mirror the PowerShell collector: a failed helper yields no
		// records rather than an entity error.
		return []schema.Record{}, nil
	}
	recs := []schema.Record{}
	for _, m := range parseNetLocalgroup(out) {
		name, domain := m, ""
		if i := strings.LastIndex(m, `\`); i >= 0 {
			domain, name = m[:i], m[i+1:]
		}
		recs = append(recs, schema.Record{
			"key":         "member:" + strings.ToLower(m),
			"name":        name,
			"domain":      anyStr(domain),
			"member_type": nil, // net.exe does not report user vs group
			"source":      "administrators",
		})
	}
	return recs, nil
}

type winPasswordPolicyCollector struct{}

func (winPasswordPolicyCollector) Name() string { return "password_policy" }
func (winPasswordPolicyCollector) Level() int   { return levelQuick }
func (winPasswordPolicyCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	out, err := assessExec(ctx, "net", "accounts")
	if err != nil {
		// Mirror the PowerShell collector: a failed helper yields no
		// records rather than an entity error.
		return []schema.Record{}, nil
	}
	m := parseNetAccounts(out)
	get := func(needles ...string) *int {
		for k, v := range m {
			for _, n := range needles {
				if strings.Contains(k, n) {
					return accountInt(v)
				}
			}
		}
		return nil
	}
	return []schema.Record{{
		"key":                      "password_policy",
		"max_password_age_days":    anyInt(get("maximum password age")),
		"min_password_age_days":    anyInt(get("minimum password age")),
		"min_password_length":      anyInt(get("minimum password length")),
		"password_history":         anyInt(get("password history")),
		"lockout_threshold":        anyInt(get("lockout threshold")),
		"lockout_duration_minutes": anyInt(get("lockout duration")),
		"lockout_reset_minutes":    anyInt(get("lockout observation")),
		"source":                   "net-accounts",
	}}, nil
}

type winUpdateHealthCollector struct{}

func (winUpdateHealthCollector) Name() string { return "update_health" }
func (winUpdateHealthCollector) Level() int   { return levelQuick }
func (winUpdateHealthCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	const wuBase = `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate`
	lastOK, _ := regString(registry.LOCAL_MACHINE, wuBase+`\Auto Update\Results\Install`, "LastSuccessTime")
	auOpt, auOK := regDWORD(registry.LOCAL_MACHINE, wuBase+`\AU`, "AUOptions")
	wsus, _ := regString(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "WUServer")
	reasons := pendingRebootReasons()
	source := "windows-update"
	if wsus != "" {
		source = "wsus"
	}
	rec := schema.Record{
		"key":                    "update_health",
		"last_success_time":      anyStr(lastOK),
		"update_source":          source,
		"wsus_server":            anyStr(wsus),
		"auto_update_option":     nil,
		"auto_updates":           nil,
		"pending_reboot":         len(reasons) > 0,
		"pending_reboot_reasons": anyStrings(reasons),
		"source":                 "windows-update",
	}
	if auOK {
		rec["auto_update_option"] = int64(auOpt)
	}
	return []schema.Record{rec}, nil
}

// pendingRebootReasons mirrors the PowerShell Test-PendingReboot indicators
// with stable slugs both implementations share.
func pendingRebootReasons() []string {
	var reasons []string
	keys := []struct {
		path string
		slug string
	}{
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`, "cbs-reboot-pending"},
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending`, "cbs-packages-pending"},
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`, "wu-reboot-required"},
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting`, "wu-post-reboot-reporting"},
	}
	for _, k := range keys {
		if regKeyExists(registry.LOCAL_MACHINE, k.path) {
			reasons = append(reasons, k.slug)
		}
	}
	if pfro, ok := regStrings(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "PendingFileRenameOperations"); ok && len(pfro) > 0 {
		reasons = append(reasons, "pending-file-rename")
	}
	return reasons
}

type winReliabilityCollector struct{}

func (winReliabilityCollector) Name() string { return "reliability" }
func (winReliabilityCollector) Level() int   { return levelFull }
func (winReliabilityCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	script := "Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008,41,1001,1074} -MaxEvents 1000 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Id=$_.Id; TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o') } } | ConvertTo-Json -Compress -Depth 3"
	out, err := assessExec(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil, err
	}
	type event struct {
		ID          int
		TimeCreated string
	}
	rows, err := decodePSRows[event](out)
	if err != nil {
		return nil, err
	}
	counts := map[int]int{}
	latest := map[int]string{}
	for _, r := range rows {
		counts[r.ID]++
		if r.TimeCreated > latest[r.ID] {
			latest[r.ID] = r.TimeCreated
		}
	}
	return []schema.Record{{
		"key":                      "reliability",
		"unexpected_shutdowns":     counts[6008],
		"kernel_power_events":      counts[41],
		"bugchecks":                counts[1001],
		"clean_shutdowns":          counts[1074],
		"last_unexpected_shutdown": anyStr(latest[6008]),
		"last_bugcheck":            anyStr(latest[1001]),
		"source":                   "event-log",
	}}, nil
}

type winMachineCertCollector struct{}

func (winMachineCertCollector) Name() string { return "machine_certs" }
func (winMachineCertCollector) Level() int   { return levelFull }
func (winMachineCertCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	// Fail loud (no SilentlyContinue): an access-denied store must surface
	// as a gated entity error, not as "no certificates".
	script := "Get-ChildItem Cert:\\LocalMachine\\My -ErrorAction Stop | Select-Object -First 200 | ForEach-Object { [pscustomobject]@{ Thumbprint=$_.Thumbprint; Subject=$_.Subject; Issuer=$_.Issuer; SerialNumber=$_.SerialNumber; NotBefore=$_.NotBefore.ToUniversalTime().ToString('o'); NotAfter=$_.NotAfter.ToUniversalTime().ToString('o'); HasPrivateKey=[bool]$_.HasPrivateKey; Purposes=((@($_.EnhancedKeyUsageList) | ForEach-Object { $_.FriendlyName }) -join ';') } } | ConvertTo-Json -Compress -Depth 3"
	out, err := assessCombined(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		msg := strings.TrimSpace(out)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("machine cert store query failed: %v: %s", err, msg)
	}
	type cert struct {
		Thumbprint    string
		Subject       string
		Issuer        string
		SerialNumber  string
		NotBefore     string
		NotAfter      string
		HasPrivateKey bool
		Purposes      string
	}
	rows, err := decodePSRows[cert](out)
	if err != nil {
		return nil, err
	}
	now := nowUTC()
	recs := []schema.Record{}
	for _, r := range rows {
		if r.Thumbprint == "" {
			continue
		}
		expiry, _ := parseISOTime(r.NotAfter)
		days := 0
		expired := false
		if !expiry.IsZero() {
			hours := expiry.Sub(now).Hours()
			days = int(hours / 24)
			expired = hours < 0
		}
		recs = append(recs, schema.Record{
			"key":             "cert:" + r.Thumbprint,
			"subject":         anyStr(r.Subject),
			"issuer":          anyStr(r.Issuer),
			"serial_number":   anyStr(r.SerialNumber),
			"thumbprint":      r.Thumbprint,
			"not_before":      anyStr(r.NotBefore),
			"not_after":       anyStr(r.NotAfter),
			"days_remaining":  days,
			"expired":         expired,
			"expiring_soon":   !expired && days < 30,
			"has_private_key": r.HasPrivateKey,
			"purposes":        anyStr(r.Purposes),
			"store":           "MY",
		})
	}
	return recs, nil
}

type winUSBHistoryCollector struct{}

func (winUSBHistoryCollector) Name() string { return "usb_history" }
func (winUSBHistoryCollector) Level() int   { return levelFull }
func (winUSBHistoryCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	const base = `SYSTEM\CurrentControlSet\Enum\USBSTOR`
	if !regKeyExists(registry.LOCAL_MACHINE, base) {
		return []schema.Record{}, nil
	}
	recs := []schema.Record{}
	for _, device := range regSubKeys(registry.LOCAL_MACHINE, base) {
		for _, serial := range regSubKeys(registry.LOCAL_MACHINE, base+`\`+device) {
			p := base + `\` + device + `\` + serial
			friendly, _ := regString(registry.LOCAL_MACHINE, p, "FriendlyName")
			container, _ := regString(registry.LOCAL_MACHINE, p, "ContainerID")
			recs = append(recs, schema.Record{
				"key":           "usbstor:" + device + ":" + serial,
				"device":        device,
				"serial":        serial,
				"friendly_name": anyStr(friendly),
				"container_id":  anyStr(container),
			})
		}
	}
	return recs, nil
}

type winRuntimeCollector struct{}

func (winRuntimeCollector) Name() string { return "runtimes" }
func (winRuntimeCollector) Level() int   { return levelQuick }
func (winRuntimeCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	recs := []schema.Record{}
	if ver, ok := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine`, "PowerShellVersion"); ok && ver != "" {
		machinePol, _ := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`, "ExecutionPolicy")
		userPol, _ := regString(registry.CURRENT_USER, `SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`, "ExecutionPolicy")
		recs = append(recs, schema.Record{
			"key": "runtime:powershell:" + ver, "kind": "powershell",
			"name": "Windows PowerShell", "version": ver, "path": nil,
			"machine_policy": anyStr(machinePol), "user_policy": anyStr(userPol),
			"source": "registry",
		})
	}
	for _, id := range regSubKeys(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShellCore\InstalledVersions`) {
		ver, ok := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\PowerShellCore\InstalledVersions\`+id, "SemanticVersion")
		if !ok || ver == "" {
			continue
		}
		recs = append(recs, schema.Record{
			"key": "runtime:powershell:" + ver, "kind": "powershell",
			"name": "PowerShell 7", "version": ver, "path": nil,
			"machine_policy": nil, "user_policy": nil, "source": "registry",
		})
	}
	if release, ok := regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full`, "Release"); ok {
		if name := dotnetFrameworkName(int(release)); name != "" {
			recs = append(recs, schema.Record{
				"key": "runtime:dotnet-framework:" + name, "kind": "dotnet-framework",
				"name": ".NET Framework", "version": name, "path": nil,
				"machine_policy": nil, "user_policy": nil, "source": "registry",
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
	recs = append(recs, browserRecords()...)
	return recs, nil
}

// browserRecords reads installed browser versions from update-registry keys.
func browserRecords() []schema.Record {
	recs := []schema.Record{}
	clients := []struct {
		name string
		slug string
		guid string
	}{
		{"Google Chrome", "chrome", "{8A69D345-D564-4135-B097-BCE2976CFCE5}"},
		{"Microsoft Edge", "edge", "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"},
	}
	roots := []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER}
	for _, c := range clients {
		for _, root := range roots {
			p := `SOFTWARE\Google\Update\Clients\` + c.guid
			if c.slug == "edge" {
				p = `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + c.guid
			}
			if ver, ok := regString(root, p, "pv"); ok && ver != "" {
				recs = append(recs, schema.Record{
					"key": "runtime:browser:" + c.slug + ":" + ver, "kind": "browser",
					"name": c.name, "version": ver, "path": nil,
					"machine_policy": nil, "user_policy": nil, "source": "registry",
				})
				break
			}
		}
	}
	const ffBase = `SOFTWARE\Mozilla\Mozilla Firefox`
	vers := []string{}
	for _, v := range regSubKeys(registry.LOCAL_MACHINE, ffBase) {
		if v != "" && v[0] >= '0' && v[0] <= '9' {
			vers = append(vers, v)
		}
	}
	if best := maxDottedVersion(vers); best != "" {
		recs = append(recs, schema.Record{
			"key": "runtime:browser:firefox:" + best, "kind": "browser",
			"name": "Mozilla Firefox", "version": best, "path": nil,
			"machine_policy": nil, "user_policy": nil, "source": "registry",
		})
	}
	return recs
}

type winRecoveryCollector struct{}

func (winRecoveryCollector) Name() string { return "recovery" }
func (winRecoveryCollector) Level() int   { return levelQuick }
func (winRecoveryCollector) Collect(ctx context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		Size uint64
		Type string
	}
	if err := wmi.Query("SELECT Size,Type FROM Win32_DiskPartition WHERE Type LIKE '%Recovery%'", &rows); err != nil {
		return nil, err
	}
	var total uint64
	for _, r := range rows {
		total += r.Size
	}
	status := "unknown"
	if out, err := assessExec(ctx, "reagentc", "/info"); err == nil {
		status = parseReagentcInfo(out)
	}
	var totalField any
	if len(rows) > 0 {
		totalField = int64(total)
	}
	return []schema.Record{{
		"key":                        "recovery",
		"recovery_partition_present": len(rows) > 0,
		"recovery_partition_count":   len(rows),
		"recovery_total_bytes":       totalField,
		"winre_status":               status,
		"source":                     "wmi+reagentc",
	}}, nil
}
