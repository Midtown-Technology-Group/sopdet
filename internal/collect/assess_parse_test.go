package collect

import (
	"strings"
	"testing"
)

func TestParseNetshWLANInterfaces(t *testing.T) {
	out := `There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Example Wireless Adapter
    Physical address       : ab:cd:ef:12:34:56
    State                  : connected
    SSID                   : CorpNet
    BSSID                  : 11:22:33:44:55:66
    Network type           : Infrastructure
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Channel                : 36
    Signal                 : 82%
`
	got := parseNetshWLANInterfaces(out)
	if len(got) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(got))
	}
	w := got[0]
	if w.Interface != "Wi-Fi" || w.SSID != "CorpNet" || w.BSSID != "11:22:33:44:55:66" {
		t.Fatalf("bad identity: %+v", w)
	}
	if w.SignalPercent == nil || *w.SignalPercent != 82 {
		t.Fatalf("bad signal: %+v", w)
	}
	if w.Channel == nil || *w.Channel != 36 {
		t.Fatalf("bad channel: %+v", w)
	}
	if w.Authentication != "WPA2-Personal" || w.Cipher != "CCMP" || w.RadioType != "802.11ac" {
		t.Fatalf("bad security: %+v", w)
	}

	disc := parseNetshWLANInterfaces("    Name : Wi-Fi\n    State : disconnected\n")
	if len(disc) != 1 || disc[0].State != "disconnected" || disc[0].SSID != "" {
		t.Fatalf("disconnected block: %+v", disc)
	}
	if got := parseNetshWLANInterfaces("The Wireless AutoConfig Service is not running.\n"); len(got) != 0 {
		t.Fatalf("expected no interfaces, got %+v", got)
	}
}

func TestParseNetshWinhttpProxy(t *testing.T) {
	p := parseNetshWinhttpProxy("Current WinHTTP proxy settings under:\n\n    Proxy Server(s) :  proxy.example:8080\n    Bypass List     :  *.example;10.*\n")
	if p.Direct || p.Server != "proxy.example:8080" || p.Bypass != "*.example;10.*" {
		t.Fatalf("proxy: %+v", p)
	}
	d := parseNetshWinhttpProxy("Current WinHTTP proxy settings under:\n\n    Direct access (no proxy server).\n")
	if !d.Direct {
		t.Fatalf("direct: %+v", d)
	}
}

func TestParseRoutePrint4(t *testing.T) {
	out := `IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.5     25
        192.168.1.0    255.255.255.0         On-link      192.168.1.5    281
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          10.9.0.0      255.255.0.0         10.9.0.1       1
`
	got := parseRoutePrint4(out)
	if len(got) != 3 {
		t.Fatalf("expected 3 routes, got %+v", got)
	}
	if got[0].Destination != "0.0.0.0" || got[0].Gateway != "192.168.1.1" || *got[0].Metric != 25 {
		t.Fatalf("default route: %+v", got[0])
	}
	if got[1].Destination != "192.168.1.0" || got[1].Gateway != "" || got[1].Interface != "192.168.1.5" {
		t.Fatalf("on-link route: %+v", got[1])
	}
	if !got[2].Persistent || got[2].Interface != "" || got[2].Destination != "10.9.0.0" {
		t.Fatalf("persistent route: %+v", got[2])
	}
}

func TestParseProcNetRoute(t *testing.T) {
	content := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
	got := parseProcNetRoute(content)
	if len(got) != 2 {
		t.Fatalf("expected 2 routes, got %+v", got)
	}
	if got[0].Gateway != "192.168.1.1" || got[0].Destination != "0.0.0.0" || *got[0].Metric != 100 {
		t.Fatalf("default: %+v", got[0])
	}
	if got[1].Mask != "255.255.255.0" || got[1].Destination != "192.168.1.0" {
		t.Fatalf("lan: %+v", got[1])
	}
	if hexLEIPv4("ZZZ") != "" || hexLEIPv4("0101A8C0") != "192.168.1.1" {
		t.Fatal("hexLEIPv4")
	}
}

func TestParseNetstatInetRoutes(t *testing.T) {
	out := `Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGSc           en0
192.168.1/24       link#4             UCS            en0      !
192.168.1.1/32     link#4             UCS            en0      !
10.0.0.1           10.0.0.254         UGSc           en1
`
	got := parseNetstatInetRoutes(out)
	if len(got) != 2 {
		t.Fatalf("expected 2 routes, got %+v", got)
	}
	if got[0].Destination != "0.0.0.0" || got[0].Gateway != "192.168.1.1" || got[0].Interface != "en0" {
		t.Fatalf("default: %+v", got[0])
	}
	if got[1].Interface != "en1" {
		t.Fatalf("second: %+v", got[1])
	}
}

func TestParseArp(t *testing.T) {
	win := "Interface: 192.168.1.5 --- 0x4\n" +
		"  Internet Address      Physical Address      Type\n" +
		"  192.168.1.1           ab-cd-ef-12-34-56     dynamic\n" +
		"  192.168.1.9           11-22-33-44-55-66     static\n"
	got := parseArpAWindows(win)
	if len(got) != 2 || got[0].Iface != "192.168.1.5" || got[0].Type != "dynamic" || got[1].Type != "static" {
		t.Fatalf("windows arp: %+v", got)
	}

	mac := "? (192.168.1.1) at ab:cd:ef:12:34:56 on en0 ifscope [ethernet]\n" +
		"? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]\n"
	gotM := parseArpADarwin(mac)
	if len(gotM) != 1 || gotM[0].MAC != "ab:cd:ef:12:34:56" || gotM[0].Iface != "en0" {
		t.Fatalf("darwin arp: %+v", gotM)
	}

	proc := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.1      0x1         0x2         ab:cd:ef:12:34:56     *        eth0\n" +
		"192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	gotL := parseProcNetArp(proc)
	if len(gotL) != 1 || gotL[0].State != "reachable" || gotL[0].Type != "dynamic" {
		t.Fatalf("proc arp: %+v", gotL)
	}
}

func TestParseSchtasksCSV(t *testing.T) {
	out := `"TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Run As User","Schedule","Schedule Type","Scheduled Task State"
` +
		`"\Microsoft\Windows\UpdateOrchestrator\Reboot","N/A","Ready","Interactive/Background","10/2/2026 3:00:00 AM","0","Microsoft","%systemroot%\system32\MusNotification.exe","SYSTEM","At 3 AM daily","Daily","Enabled"
` +
		`"\Custom\Nightly","10/4/2026 1:00:00 AM","Running","Interactive only","10/3/2026 1:00:05 AM","267011","Admin","C:\Tools\job.exe /q","Admin","At 1 AM","Daily","Disabled"
`
	got := parseSchtasksCSV(out)
	if len(got) != 2 {
		t.Fatalf("expected 2 tasks, got %+v", got)
	}
	if got[0].TaskName != `\Microsoft\Windows\UpdateOrchestrator\Reboot` || got[0].LastResult != "0" {
		t.Fatalf("first: %+v", got[0])
	}
	if got[0].Enabled == nil || !*got[0].Enabled {
		t.Fatalf("first enabled: %+v", got[0])
	}
	if got[1].Enabled == nil || *got[1].Enabled || got[1].Command != `C:\Tools\job.exe /q` {
		t.Fatalf("second: %+v", got[1])
	}
	if got := parseSchtasksCSV("not,csv\n"); len(got) != 0 {
		t.Fatalf("garbage should yield nothing: %+v", got)
	}
	withErr := "ERROR: Access is denied.\n\"TaskName\",\"Status\"\n\"\\T\",\"Ready\"\nERROR: The system cannot find the file specified.\n"
	gotErr := parseSchtasksCSV(withErr)
	if len(gotErr) != 1 || gotErr[0].TaskName != `\T` || gotErr[0].Status != "Ready" {
		t.Fatalf("error lines should be skipped: %+v", gotErr)
	}
	withBOM := "\ufeff\"TaskName\",\"Status\"\n\"\\T\",\"Ready\"\n"
	gotBOM := parseSchtasksCSV(withBOM)
	if len(gotBOM) != 1 || gotBOM[0].TaskName != `\T` {
		t.Fatalf("BOM header should parse: %+v", gotBOM)
	}
}

func TestParseNetLocalgroup(t *testing.T) {
	out := "Alias name     administrators\nMembers\n\n" +
		"-----------------------------------------------------------------------------\n" +
		"Administrator\nEXAMPLE\\jdoe\n" +
		"The command completed successfully.\n"
	got := parseNetLocalgroup(out)
	if len(got) != 2 || got[0] != "Administrator" || got[1] != `EXAMPLE\jdoe` {
		t.Fatalf("members: %q", got)
	}
}

func TestParseNetAccounts(t *testing.T) {
	out := "Minimum password age (days):                          1\n" +
		"Maximum password age (days):                          42\n" +
		"Minimum password length:                              8\n" +
		"Length of password history maintained:                24\n" +
		"Lockout threshold:                                    5\n" +
		"Lockout duration (minutes):                           30\n" +
		"Lockout observation window (minutes):                 30\n"
	m := parseNetAccounts(out)
	if m["maximum password age (days)"] != "42" || m["lockout threshold"] != "5" {
		t.Fatalf("accounts: %v", m)
	}
	if accountInt("42") == nil || *accountInt("42") != 42 {
		t.Fatal("accountInt numeric")
	}
	if accountInt("Never") != nil || accountInt("") != nil {
		t.Fatal("accountInt unlimited should be nil")
	}
}

func TestParseLastWTMP(t *testing.T) {
	out := "reboot   system boot  6.8.0-60-generic Fri Oct  3 09:15   still running\n" +
		"shutdown system down  6.8.0-60-generic Thu Oct  2 18:00 - 18:01  (00:01)\n" +
		"ops      pts/0        10.0.0.9         Wed Oct  1 12:00 - crash  (01:00)\n" +
		"wtmp begins Wed Oct  1 00:00:00 2026\n"
	s := parseLastWTMP(out, 2026)
	if s.Reboots != 1 || s.Shutdowns != 1 || s.Crashes != 1 {
		t.Fatalf("counts: %+v", s)
	}
	if !strings.HasPrefix(s.LastReboot, "2026-10-03T09:15") {
		t.Fatalf("last reboot: %q", s.LastReboot)
	}
	if !strings.HasPrefix(s.LastCrash, "2026-10-01T12:00") {
		t.Fatalf("last crash: %q", s.LastCrash)
	}
}

func TestParseSystemctlTimers(t *testing.T) {
	out := "NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES\n" +
		"Mon 2026-10-05 00:00:00 UTC  1 day left    Sun 2026-10-04 00:00:11 UTC  9h ago       logrotate.timer              logrotate.service\n" +
		"n/a                            n/a           n/a                          n/a          stale.timer                  stale.service\n" +
		"\n2 timers listed.\n"
	got := parseSystemctlTimers(out)
	if len(got) != 2 {
		t.Fatalf("expected 2 timers, got %+v", got)
	}
	if got[0].Unit != "logrotate.timer" || got[0].Activates != "logrotate.service" {
		t.Fatalf("first: %+v", got[0])
	}
	if !strings.HasPrefix(got[0].Next, "Mon 2026-10-05") || !strings.HasPrefix(got[0].Last, "Sun 2026-10-04") {
		t.Fatalf("first dates: %+v", got[0])
	}
	if got[1].Unit != "stale.timer" || got[1].Next != "" {
		t.Fatalf("stale: %+v", got[1])
	}
}

func TestParseLaunchctlList(t *testing.T) {
	out := "PID\tStatus\tLabel\n-\t0\tcom.apple.Finder\n1234\t0\tcom.example.agent\n-\t78\tcom.example.failed\n"
	got := parseLaunchctlList(out)
	if len(got) != 3 || got[1].Label != "com.example.agent" || got[1].PID != "1234" {
		t.Fatalf("launchctl: %+v", got)
	}
	if got[2].Status != "78" {
		t.Fatalf("failed status: %+v", got[2])
	}
}

func TestParseCrontabFile(t *testing.T) {
	content := "SHELL=/bin/sh\n# comment\n\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n@reboot root /usr/local/bin/agent start\n"
	got := parseCrontabFile(content, true)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %+v", got)
	}
	if got[0].Schedule != "17 * * * *" || got[0].User != "root" || !strings.HasPrefix(got[0].Command, "cd /") {
		t.Fatalf("first: %+v", got[0])
	}
	if got[1].Schedule != "@reboot" || got[1].Command != "/usr/local/bin/agent start" {
		t.Fatalf("reboot: %+v", got[1])
	}
	user := parseCrontabFile("0 1 * * * /home/u/backup.sh\n", false)
	if len(user) != 1 || user[0].User != "" || user[0].Command != "/home/u/backup.sh" {
		t.Fatalf("user crontab: %+v", user)
	}
}

func TestParseResolvConf(t *testing.T) {
	r := parseResolvConf("# comment\nnameserver 192.168.1.1\nnameserver 1.1.1.1\nsearch example.local\n")
	if len(r.Servers) != 2 || r.Servers[0] != "192.168.1.1" || r.Domain != "example.local" {
		t.Fatalf("resolv: %+v", r)
	}
}

func TestParseDotnetRuntimes(t *testing.T) {
	out := "Microsoft.NETCore.App 8.0.3 [/usr/lib/dotnet/shared/Microsoft.NETCore.App]\n" +
		"Microsoft.AspNetCore.App 8.0.3 [/usr/lib/dotnet/shared/Microsoft.AspNetCore.App]\n"
	got := parseDotnetRuntimes(out)
	if len(got) != 2 || got[0].Name != "Microsoft.NETCore.App" || got[0].Version != "8.0.3" {
		t.Fatalf("runtimes: %+v", got)
	}
}

func TestParseSshdConfig(t *testing.T) {
	content := "# comment\nPort 2222\nPermitRootLogin no\nPasswordAuthentication yes\nPermitRootLogin yes\nMatch User ops\n  PermitRootLogin yes\n"
	m := parseSshdConfig(content)
	if m["port"] != "2222" || m["permitrootlogin"] != "no" || m["passwordauthentication"] != "yes" {
		t.Fatalf("sshd (first wins): %v", m)
	}
}

func TestParseLoginDefs(t *testing.T) {
	m := parseLoginDefs("# comment\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\n")
	if m["PASS_MAX_DAYS"] != "99999" || m["PASS_MIN_DAYS"] != "0" {
		t.Fatalf("login.defs: %v", m)
	}
}

func TestParseQuser(t *testing.T) {
	out := " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n" +
		">ops                  console             1  Active      none   10/3/2026 9:00 AM\n" +
		" svc                  rdp-tcp#0           2  Disc        1:20   10/2/2026 5:00 PM\n"
	got := parseQuser(out)
	if len(got) != 1 || got[0].User != "ops" || got[0].Session != "console" {
		t.Fatalf("quser (disc skipped): %+v", got)
	}
	if !strings.HasPrefix(got[0].LogonTime, "Active") {
		t.Fatalf("logon time: %+v", got[0])
	}
}

func TestParseReagentcInfo(t *testing.T) {
	if s := parseReagentcInfo("Windows RE status:         Enabled\n"); s != "Enabled" {
		t.Fatalf("enabled: %q", s)
	}
	if s := parseReagentcInfo("Windows RE status:         Disabled\n"); s != "Disabled" {
		t.Fatalf("disabled: %q", s)
	}
	if s := parseReagentcInfo("REAGENTC.EXE: Operation failed: 70\n"); s != "unknown" {
		t.Fatalf("failure: %q", s)
	}
}

func TestParseMacInstallHistory(t *testing.T) {
	plist := `<?xml version="1.0"?><plist><array><dict><key>date</key><date>2026-09-01T10:00:00Z</date></dict>` +
		`<dict><key>date</key><date>2026-09-20T10:00:00Z</date></dict></array></plist>`
	latest, n := parseMacInstallHistory(plist)
	if latest != "2026-09-20T10:00:00Z" || n != 2 {
		t.Fatalf("history: %q %d", latest, n)
	}
}

func TestParsePwpolicyAccountPolicies(t *testing.T) {
	plist := `<key>minimumLength</key><integer>8</integer><key>maxFailedLoginAttempts</key><integer>3</integer>`
	m := parsePwpolicyAccountPolicies(plist)
	if m["min_chars"] != 8 || m["max_failed_logins"] != 3 {
		t.Fatalf("pwpolicy: %v", m)
	}
}

func TestParseScutilProxy(t *testing.T) {
	out := "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : proxy.example\n  HTTPPort : 8080\n  ProxyAutoConfigURLString : http://example/proxy.pac\n}\n"
	p := parseScutilProxy(out)
	if !p.Enabled || p.Server != "proxy.example:8080" || p.Autoconfig != "http://example/proxy.pac" {
		t.Fatalf("proxy: %+v", p)
	}
	off := parseScutilProxy("<dictionary> {\n  HTTPEnable : 0\n}\n")
	if off.Enabled || off.Server != "" {
		t.Fatalf("proxy off: %+v", off)
	}
}

func TestParseIwLink(t *testing.T) {
	out := "Connected to 11:22:33:44:55:66 (on wlan0)\n\tSSID: CorpNet\n\tfreq: 5180\n\tsignal: -52 dBm\n"
	l := parseIwLink(out)
	if !l.Connected || l.SSID != "CorpNet" || l.BSSID != "11:22:33:44:55:66" {
		t.Fatalf("link: %+v", l)
	}
	if l.SignalDbm == nil || *l.SignalDbm != -52 || freqToChannel(*l.Freq) != 36 {
		t.Fatalf("signal/freq: %+v", l)
	}
	if l := parseIwLink("Not connected.\n"); l.Connected {
		t.Fatalf("not connected: %+v", l)
	}
	if freqToChannel(2412) != 1 || freqToChannel(2484) != 14 || freqToChannel(9999) != 0 {
		t.Fatal("freqToChannel")
	}
}

func TestSplitCIDRAndMAC(t *testing.T) {
	h, m := splitCIDR("192.168.1.5/24")
	if h != "192.168.1.5" || m != "255.255.255.0" {
		t.Fatalf("cidr: %q %q", h, m)
	}
	if normalizeMAC("AB-CD-EF-12-34-56") != "abcdef123456" {
		t.Fatal("normalizeMAC")
	}
	if normalizeMAC("ab:cd:ef:12:34:56") != "abcdef123456" {
		t.Fatal("normalizeMAC colons")
	}
}

func TestDotnetFrameworkName(t *testing.T) {
	cases := map[int]string{533320: "4.8.1", 528040: "4.8", 461808: "4.7.2", 394254: "4.6.1", 378389: "4.5", 100: ""}
	for in, want := range cases {
		if got := dotnetFrameworkName(in); got != want {
			t.Fatalf("release %d: got %q want %q", in, got, want)
		}
	}
	if nlmCategoryName(0) != "public" || nlmCategoryName(1) != "private" || nlmCategoryName(2) != "domain" || nlmCategoryName(9) != "unknown" {
		t.Fatal("nlmCategoryName")
	}
}

func TestDottedVersion(t *testing.T) {
	if v := dottedVersion("Python 3.11.2\n"); v != "3.11.2" {
		t.Fatalf("python: %q", v)
	}
	if v := dottedVersion("Google Chrome 120.0.6099.109 \n"); v != "120.0.6099.109" {
		t.Fatalf("chrome: %q", v)
	}
	if v := dottedVersion("no version here"); v != "" {
		t.Fatalf("none: %q", v)
	}
}

func TestMaxDottedVersion(t *testing.T) {
	if v := maxDottedVersion([]string{"91.0", "115.0.1", "102.9"}); v != "115.0.1" {
		t.Fatalf("max: %q", v)
	}
	if v := maxDottedVersion([]string{"9.0", "10.0"}); v != "10.0" {
		t.Fatalf("numeric compare: %q", v)
	}
	if v := maxDottedVersion(nil); v != "" {
		t.Fatalf("empty: %q", v)
	}
}

func TestAnyHelpers(t *testing.T) {
	if anyStr("") != nil || anyStr("x") != "x" {
		t.Fatal("anyStr")
	}
	n := 3
	if anyInt(nil) != nil || anyInt(&n) != 3 {
		t.Fatal("anyInt")
	}
	if anyInt64(5, false) != nil || anyInt64(5, true) != int64(5) {
		t.Fatal("anyInt64")
	}
	b := true
	if anyBool(nil) != nil || anyBool(&b) != true {
		t.Fatal("anyBool")
	}
	if s := anyStrings(nil).([]string); len(s) != 0 {
		t.Fatal("anyStrings nil should be empty array")
	}
}

func TestParseMacHelpers(t *testing.T) {
	ports := parseNetworksetupPorts("Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: ab:cd\n\nHardware Port: Thunderbolt\nDevice: en1\n")
	if ports["Wi-Fi"] != "en0" || ports["Thunderbolt"] != "en1" {
		t.Fatalf("ports: %v", ports)
	}
	a := parseAirportI("     agrCtlRSSI: -55\n     BSSID: 11:22:33:44:55:66\n     SSID: CorpNet\n     channel: 36,80\n     link auth: wpa2-psk\n")
	if a.SSID != "CorpNet" || a.BSSID != "11:22:33:44:55:66" || a.Auth != "wpa2-psk" {
		t.Fatalf("airport: %+v", a)
	}
	if a.RSSI == nil || *a.RSSI != -55 {
		t.Fatalf("airport rssi: %+v", a)
	}
	if a.Channel == nil || *a.Channel != 36 {
		t.Fatalf("airport channel: %+v", a)
	}
	gw, iface := parseRouteGetDefault("   route to: default\ngateway: 192.168.1.1\ninterface: en0\n")
	if gw != "192.168.1.1" || iface != "en0" {
		t.Fatalf("route get: %q %q", gw, iface)
	}
	uids := parseDscacheutilUIDs("name: root\nuid: 0\nname: ops\nuid: 501\nname: toor\nuid: 0\n", "0")
	if len(uids) != 2 || uids[1] != "toor" {
		t.Fatalf("dscacheutil: %v", uids)
	}
	if sshdOpt(map[string]string{"a": "b"}, "a") != "b" || sshdOpt(map[string]string{}, "a") != "default" {
		t.Fatal("sshdOpt")
	}
}

func TestParseISOTime(t *testing.T) {
	if _, err := parseISOTime("2026-10-03T09:15:00.0000000Z"); err != nil {
		t.Fatalf("rfc3339nano: %v", err)
	}
	if _, err := parseISOTime("2026-10-03T09:15:00Z"); err != nil {
		t.Fatalf("rfc3339: %v", err)
	}
	if _, err := parseISOTime("2026-10-02 03:00:00"); err != nil {
		t.Fatalf("space-separated: %v", err)
	}
	if _, err := parseISOTime("not a time"); err == nil {
		t.Fatal("garbage should fail")
	}
}
