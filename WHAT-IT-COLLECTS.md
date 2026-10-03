# What this collects

Read-only. One JSON envelope per scan. Every entity record carries a stable
`key`, a content `fingerprint`, and an `observed_at` timestamp. Fields that
cannot be read without administrator rights are reported as unavailable rather
than guessed; a failed collection appears in `entity_errors` with
`gated: true`.

## Identity and hardware
- Hostname, FQDN, domain/workgroup, domain role, chassis type, asset tag
- Manufacturer, model, system type, VM detection (VMware, Hyper-V, VirtualBox, QEMU, Xen, Parallels)
- Machine GUID, SMBIOS hardware UUID, BIOS/baseboard/enclosure serials
- BIOS vendor, version, release date, SKU; baseboard vendor/product
- Processors: model, cores, logical cores, clock, socket, cache
- Memory modules: size, speed, form factor, manufacturer, part/serial
- Graphics adapters: model, vendor, VRAM, driver version
- Physical disks: model, serial, size, interface, media type, partitions
- Batteries: chemistry, status, charge, design vs. full-charge capacity (capacity/cycle count may require admin)

## Operating system
- Name, edition, version, build, update revision (UBR), release/codename
- Install date, last boot time, uptime, locale, language, time zone
- Pending-reboot state, Secure Boot state, hypervisor presence
- OS serial number, activation SKU

## Software and updates
- Installed programs from the machine and user uninstall registry hives: name, version, publisher, install date, install location, size, architecture, MSI/exe format, product code
- Store/UWP packages (when `includeAppx`)
- OS hotfixes (KB) with install date and installer
- Drivers: device, class, provider, version, date, signing state (full profile)

## Security posture
- Antivirus products and enabled state; Windows Defender version, signature version/age, tamper protection
- Firewall profiles and default actions
- UAC configuration
- TPM presence, version, activation/ownership (may require admin)
- Volume encryption name/algorithm/status where readable

## Network and storage
- Adapters: MAC, IP addresses, subnets, gateways, DNS, DHCP state, link speed
- Listening TCP/UDP ports with owning process (full profile; ephemeral ports excluded)
- Logical volumes: drive letter, label, filesystem, capacity, free space, serial, encryption state
- Printers, monitors, USB devices (full profile)
- Physical disk health: SMART status and predictive-failure flag

## Network fingerprinting (read-only; nothing is scanned, probed, or captured)
- IPv4 route table (active + persistent) and ARP/neighbor table entries
- Network location profiles: name, public/private/domain category
- Wi-Fi association per interface: SSID, BSSID, signal, auth/cipher (current link only, no scan)
- Proxy configuration: per-user server/bypass/PAC URL and system (WinHTTP/scutil) proxy

## Assessment posture
- Scheduled tasks (Windows), cron/systemd timers (Linux), launchd jobs (macOS): schedule, command, author, last result. Note: schtasks column names follow the OS display language on non-English systems (positional fallback).
- Remote-access posture: RDP state/port/NLA, SMBv1 client/server, LLMNR, NetBIOS mode, WinRM (Windows); sshd config: installed, permit-root-login, password-auth, port (Linux/macOS)
- Privileged members: local Administrators (Windows); sudo/wheel/admin/docker groups plus extra uid-0 accounts (Linux/macOS)
- Password and lockout policy: max/min age, min length, history, lockout threshold/duration
- Update health: last success time, Windows Update vs WSUS source, pending-reboot state with reasons
- Reliability: unexpected-shutdown, kernel-power, bugcheck, and clean-shutdown counters with latest timestamps
- Machine-store certificate expiry: subject, issuer, dates, expired/expiring flags (no private key material; may report gated without read access)
- USB storage history: previously attached devices by serial (registry history, not just connected)
- Runtimes: PowerShell/.NET versions and execution policy, `dotnet` runtimes, installed browser versions
- Recovery: recovery-partition presence and WinRE status (Windows)

## Deliberately not collected
- File contents, user documents, browser history, credentials, passwords, tokens or secrets
- Screenshots, keystrokes, or anything from user sessions
- Network traffic, packet data, or live telemetry

## Not done to the machine
- No installation, service, or scheduled task
- No registry or configuration writes (outside an optional per-user state file for delta runs)
- No elevation; no privilege escalation
