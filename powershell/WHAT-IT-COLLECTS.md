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

## Deliberately not collected
- File contents, user documents, browser history, credentials, passwords, tokens or secrets
- Screenshots, keystrokes, or anything from user sessions
- Network traffic, packet data, or live telemetry

## Not done to the machine
- No installation, service, or scheduled task
- No registry or configuration writes (outside an optional per-user state file for delta runs)
- No elevation; no privilege escalation
