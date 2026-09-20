//go:build windows

package collect

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"

	"github.com/Midtown-Technology-Group/sopdet/internal/schema"
)

func init() {
	wmi.DefaultClient.AllowMissingFields = true
}

// wmiCollectors returns the Windows entities.
func wmiCollectors() []Collector {
	return []Collector{
		winOSCollector{},
		winHardwareCollector{},
		winVirtualizationCollector{},
		winSecureBootCollector{},
		winUACCollector{},
		winFirewallCollector{},
		winProcessorCollector{},
		winMemoryCollector{},
		winGraphicsCollector{},
		winBiosCollector{},
		winTPMCollector{},
		winOSPatchCollector{},
		winLocalUserCollector{},
		winLoggedOnUserCollector{},
		winPrinterCollector{},
		winBatteryCollector{},
		winAntivirusCollector{},
		winServiceCollector{},
		winDriverCollector{},
		winPhysicalDiskCollector{},
		winListeningPortCollector{},
		winUSBCollector{},
		winStartupCollector{},
		winMonitorCollector{},
		winAppxCollector{},
	}
}

func vmSystemFrom(manufacturer, model string, hypervisor bool) string {
	m := strings.ToLower(manufacturer + " " + model)
	switch {
	case strings.Contains(m, "vmware"):
		return "VMware"
	case strings.Contains(m, "virtualbox"):
		return "VirtualBox"
	case strings.Contains(m, "hyper-v") || strings.Contains(m, "virtual machine"):
		return "Hyper-V"
	case strings.Contains(m, "qemu") || strings.Contains(m, "kvm"):
		return "QEMU"
	case strings.Contains(m, "parallels"):
		return "Parallels"
	case strings.Contains(m, "xen"):
		return "Xen"
	case hypervisor:
		return "Hypervisor"
	default:
		return "Physical"
	}
}

type winOS struct {
	Caption                string
	Version                string
	BuildNumber            string
	OSArchitecture         string
	SerialNumber           string
	InstallDate            time.Time
	LastBootUpTime         time.Time
	Locale                 string
	MUILanguages           []string
	OperatingSystemSKU     uint32
	TotalVisibleMemorySize uint64
}

type winOSCollector struct{}

func (winOSCollector) Name() string { return "os" }
func (winOSCollector) Level() int   { return levelMinimal }
func (winOSCollector) Collect(_ context.Context, s *Session) ([]schema.Record, error) {
	var rows []winOS
	if err := wmi.Query("SELECT Caption,Version,BuildNumber,OSArchitecture,SerialNumber,InstallDate,LastBootUpTime,Locale,MUILanguages,OperatingSystemSKU FROM Win32_OperatingSystem", &rows); err != nil {
		return nil, err
	}
	rec := schema.Record{"key": "os", "hostname": s.Identity.Hostname, "platform": "windows", "platform_like": "windows"}
	if len(rows) > 0 {
		r := rows[0]
		rec["name"] = r.Caption
		rec["version"] = r.Version
		rec["build"] = r.BuildNumber
		rec["arch"] = r.OSArchitecture
		rec["serial_number"] = r.SerialNumber
		rec["locale"] = r.Locale
		rec["language"] = strings.Join(r.MUILanguages, ",")
		rec["edition_sku"] = r.OperatingSystemSKU
		rec["install_date"] = r.InstallDate.Format(time.RFC3339)
		rec["boot_time"] = r.LastBootUpTime.Format(time.RFC3339)
		if !r.LastBootUpTime.IsZero() {
			rec["uptime_seconds"] = int64(time.Since(r.LastBootUpTime).Seconds())
		}
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		defer k.Close()
		readString := func(name string) string { v, _, _ := k.GetStringValue(name); return v }
		rec["full_name"] = readString("ProductName")
		rec["edition_id"] = readString("EditionID")
		rec["release_id"] = readString("ReleaseId")
		rec["codename"] = readString("DisplayVersion")
		if ubr, _, err := k.GetIntegerValue("UBR"); err == nil {
			rec["revision"] = ubr
		}
	}
	return []schema.Record{rec}, nil
}

type winComputerSystem struct {
	Manufacturer        string
	Model               string
	SystemType          string
	Domain              string
	PartOfDomain        bool
	Workgroup           string
	UserName            string
	HypervisorPresent   bool
	TotalPhysicalMemory uint64
	DomainRole          uint16
	SystemFamily        string
}

func (winHardwareCollector) Name() string { return "hardware" }
func (winHardwareCollector) Level() int   { return levelMinimal }
func (winHardwareCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var cs []winComputerSystem
	if err := wmi.Query("SELECT Manufacturer,Model,SystemType,Domain,PartOfDomain,Workgroup,TotalPhysicalMemory,HypervisorPresent FROM Win32_ComputerSystem", &cs); err != nil {
		return nil, err
	}
	rec := schema.Record{"key": "hardware"}
	if len(cs) > 0 {
		rec["manufacturer"] = cs[0].Manufacturer
		rec["model"] = cs[0].Model
		rec["system_type"] = cs[0].SystemType
		rec["ram_total_bytes"] = int64(cs[0].TotalPhysicalMemory)
		rec["vm_system"] = vmSystemFrom(cs[0].Manufacturer, cs[0].Model, cs[0].HypervisorPresent)
		rec["virtual_machine"] = rec["vm_system"] != "Physical"
	}
	var bb []struct {
		Manufacturer string
		Product      string
		SerialNumber string
	}
	if err := wmi.Query("SELECT Manufacturer,Product,SerialNumber FROM Win32_BaseBoard", &bb); err == nil && len(bb) > 0 {
		rec["board_manufacturer"] = bb[0].Manufacturer
		rec["board_product"] = bb[0].Product
		rec["board_serial"] = bb[0].SerialNumber
	}
	return []schema.Record{rec}, nil
}

type winHardwareCollector struct{}

type winVirtualizationCollector struct{}

func (winVirtualizationCollector) Name() string { return "virtualization" }
func (winVirtualizationCollector) Level() int   { return levelMinimal }
func (winVirtualizationCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var cs []winComputerSystem
	if err := wmi.Query("SELECT Manufacturer,Model,HypervisorPresent FROM Win32_ComputerSystem", &cs); err != nil {
		return nil, err
	}
	vm := "Physical"
	hv := false
	if len(cs) > 0 {
		vm = vmSystemFrom(cs[0].Manufacturer, cs[0].Model, cs[0].HypervisorPresent)
		hv = cs[0].HypervisorPresent
	}
	return []schema.Record{{"key": "virtualization", "vm_system": vm, "hypervisor_present": hv, "physical": vm == "Physical"}}, nil
}

type winSecureBootCollector struct{}

func (winSecureBootCollector) Name() string { return "secureboot" }
func (winSecureBootCollector) Level() int   { return levelMinimal }
func (winSecureBootCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var value *uint64
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if v, _, err := k.GetIntegerValue("UEFISecureBootEnabled"); err == nil {
			value = &v
		}
	}
	return []schema.Record{{"key": "secureboot", "secure_boot": value, "source": "registry"}}, nil
}

type winProcessorCollector struct{}

func (winProcessorCollector) Name() string { return "processors" }
func (winProcessorCollector) Level() int   { return levelQuick }
func (winProcessorCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		DeviceID                  string
		Name                      string
		Manufacturer              string
		NumberOfCores             uint32
		NumberOfLogicalProcessors uint32
		MaxClockSpeed             uint32
		CurrentClockSpeed         uint32
		SocketDesignation         string
		ProcessorId               string
		L2CacheSize               uint32
		L3CacheSize               uint32
		AddressWidth              uint16
	}
	if err := wmi.Query("SELECT DeviceID,Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,CurrentClockSpeed,SocketDesignation,ProcessorId,L2CacheSize,L3CacheSize,AddressWidth FROM Win32_Processor", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		arch := "x86"
		if r.AddressWidth == 64 {
			arch = "x86_64"
		}
		out = append(out, schema.Record{
			"key": "cpu:" + r.DeviceID, "name": r.Name, "manufacturer": r.Manufacturer,
			"architecture": arch, "cores": r.NumberOfCores, "logical_cores": r.NumberOfLogicalProcessors,
			"current_mhz": r.CurrentClockSpeed, "max_mhz": r.MaxClockSpeed,
			"socket": r.SocketDesignation, "processor_id": r.ProcessorId,
			"l2_cache_kb": r.L2CacheSize, "l3_cache_kb": r.L3CacheSize,
		})
	}
	return out, nil
}

type winMemoryCollector struct{}

func (winMemoryCollector) Name() string { return "memory_modules" }
func (winMemoryCollector) Level() int   { return levelQuick }
func (winMemoryCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		BankLabel            string
		DeviceLocator        string
		Capacity             uint64
		Speed                uint32
		ConfiguredClockSpeed uint32
		Manufacturer         string
		PartNumber           string
		SerialNumber         string
		SMBIOSMemoryType     uint32
		FormFactor           uint32
	}
	if err := wmi.Query("SELECT BankLabel,DeviceLocator,Capacity,Speed,ConfiguredClockSpeed,Manufacturer,PartNumber,SerialNumber,SMBIOSMemoryType,FormFactor FROM Win32_PhysicalMemory", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		if r.Capacity == 0 {
			continue
		}
		out = append(out, schema.Record{
			"key":        "dimm:" + r.DeviceLocator + ":" + r.SerialNumber,
			"bank_label": r.BankLabel, "device_locator": r.DeviceLocator,
			"size_bytes": int64(r.Capacity), "form_factor": r.FormFactor,
			"memory_type": r.SMBIOSMemoryType, "speed_mts": r.Speed,
			"configured_speed_mts": r.ConfiguredClockSpeed, "manufacturer": r.Manufacturer,
			"part_number": r.PartNumber, "serial_number": r.SerialNumber,
		})
	}
	return out, nil
}

type winGraphicsCollector struct{}

func (winGraphicsCollector) Name() string { return "graphics" }
func (winGraphicsCollector) Level() int   { return levelQuick }
func (winGraphicsCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		DeviceID                    string
		Name                        string
		AdapterCompatibility        string
		AdapterRAM                  uint32
		DriverVersion               string
		DriverDate                  string
		VideoProcessor              string
		CurrentHorizontalResolution uint32
		CurrentVerticalResolution   uint32
	}
	if err := wmi.Query("SELECT DeviceID,Name,AdapterCompatibility,AdapterRAM,DriverVersion,DriverDate,VideoProcessor,CurrentHorizontalResolution,CurrentVerticalResolution FROM Win32_VideoController", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		res := ""
		if r.CurrentHorizontalResolution > 0 {
			res = strconv.Itoa(int(r.CurrentHorizontalResolution)) + "x" + strconv.Itoa(int(r.CurrentVerticalResolution))
		}
		out = append(out, schema.Record{
			"key": "gpu:" + r.DeviceID, "name": r.Name, "vendor": r.AdapterCompatibility,
			"memory_bytes": int64(r.AdapterRAM), "driver_version": r.DriverVersion,
			"driver_date": r.DriverDate, "video_processor": r.VideoProcessor,
			"resolution": res,
		})
	}
	return out, nil
}

type winBiosCollector struct{}

func (winBiosCollector) Name() string { return "bios" }
func (winBiosCollector) Level() int   { return levelQuick }
func (winBiosCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	rec := schema.Record{"key": "bios"}
	var bios []struct {
		Manufacturer       string
		Name               string
		SMBIOSBIOSVersion  string
		SerialNumber       string
		ReleaseDate        time.Time
		SystemSKUNumber    string
		SMBIOSMajorVersion uint16
		SMBIOSMinorVersion uint16
	}
	if err := wmi.Query("SELECT Manufacturer,Name,SMBIOSBIOSVersion,SerialNumber,ReleaseDate,SystemSKUNumber,SMBIOSMajorVersion,SMBIOSMinorVersion FROM Win32_BIOS", &bios); err == nil && len(bios) > 0 {
		b := bios[0]
		rec["manufacturer"] = b.Manufacturer
		rec["name"] = b.Name
		rec["version"] = b.SMBIOSBIOSVersion
		rec["bios_serial"] = b.SerialNumber
		rec["system_serial"] = b.SerialNumber
		rec["sku_number"] = b.SystemSKUNumber
		rec["release_date"] = b.ReleaseDate
		rec["smbios_major"] = b.SMBIOSMajorVersion
		rec["smbios_minor"] = b.SMBIOSMinorVersion
	}
	var enc []struct {
		SMBIOSAssetTag string
		SerialNumber   string
		ChassisTypes   []int32
	}
	if err := wmi.Query("SELECT SMBIOSAssetTag,SerialNumber,ChassisTypes FROM Win32_SystemEnclosure", &enc); err == nil && len(enc) > 0 {
		rec["asset_tag"] = enc[0].SMBIOSAssetTag
		rec["enclosure_serial"] = enc[0].SerialNumber
		chassis := make([]string, 0, len(enc[0].ChassisTypes))
		for _, c := range enc[0].ChassisTypes {
			chassis = append(chassis, strconv.Itoa(int(c)))
		}
		rec["chassis_types"] = strings.Join(chassis, ",")
	}
	return []schema.Record{rec}, nil
}

type winTPMCollector struct{}

func (winTPMCollector) Name() string { return "tpm" }
func (winTPMCollector) Level() int   { return levelQuick }
func (winTPMCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		IsEnabled_InitialValue      bool
		IsActivated_InitialValue    bool
		IsOwned_InitialValue        bool
		ManufacturerId              uint32
		ManufacturerVersion         string
		SpecVersion                 string
		PhysicalPresenceVersionInfo string
	}
	err := wmi.QueryNamespace("SELECT IsEnabled_InitialValue,IsActivated_InitialValue,IsOwned_InitialValue,ManufacturerId,ManufacturerVersion,SpecVersion,PhysicalPresenceVersionInfo FROM Win32_Tpm", &rows, "root\\cimv2\\security\\microsofttpm")
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []schema.Record{{"key": "tpm", "present": false}}, nil
	}
	r := rows[0]
	return []schema.Record{{
		"key": "tpm", "present": true, "enabled": r.IsEnabled_InitialValue,
		"activated": r.IsActivated_InitialValue, "owned": r.IsOwned_InitialValue,
		"manufacturer_id": r.ManufacturerId, "manufacturer_version": r.ManufacturerVersion,
		"spec_version": r.SpecVersion, "physical_presence_version": r.PhysicalPresenceVersionInfo,
	}}, nil
}

type winOSPatchCollector struct{}

func (winOSPatchCollector) Name() string { return "os_patches" }
func (winOSPatchCollector) Level() int   { return levelQuick }
func (winOSPatchCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		HotFixID    string
		Caption     string
		Description string
		InstalledBy string
		InstalledOn string
	}
	if err := wmi.Query("SELECT HotFixID,Caption,Description,InstalledBy,InstalledOn FROM Win32_QuickFixEngineering", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key": "patch:" + r.HotFixID, "hotfix_id": r.HotFixID, "caption": r.Caption,
			"description": r.Description, "installed_by": r.InstalledBy,
			"installed_on": r.InstalledOn, "status": "installed", "type": "os",
		})
	}
	return out, nil
}

type winLocalUserCollector struct{}

func (winLocalUserCollector) Name() string { return "local_users" }
func (winLocalUserCollector) Level() int   { return levelQuick }
func (winLocalUserCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		Name             string
		FullName         string
		Description      string
		Disabled         bool
		PasswordRequired bool
		SID              string
		Domain           string
	}
	if err := wmi.Query("SELECT Name,FullName,Description,Disabled,PasswordRequired,SID,Domain FROM Win32_UserAccount WHERE LocalAccount=True", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key": "user:" + r.SID, "name": r.Name, "full_name": r.FullName,
			"description": r.Description, "enabled": !r.Disabled, "disabled": r.Disabled,
			"password_required": r.PasswordRequired, "sid": r.SID, "account_type": "local",
		})
	}
	return out, nil
}

type winPrinterCollector struct{}

func (winPrinterCollector) Name() string { return "printers" }
func (winPrinterCollector) Level() int   { return levelQuick }
func (winPrinterCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		Name          string
		Default       bool
		Network       bool
		Shared        bool
		PortName      string
		DriverName    string
		PrinterStatus uint16
		Location      string
	}
	if err := wmi.Query("SELECT Name,Default,Network,Shared,PortName,DriverName,PrinterStatus,Location FROM Win32_Printer", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key": "printer:" + r.Name, "name": r.Name, "default": r.Default,
			"network": r.Network, "shared": r.Shared, "port_name": r.PortName,
			"driver_name": r.DriverName, "status": r.PrinterStatus, "location": r.Location,
		})
	}
	return out, nil
}

type winBatteryCollector struct{}

func (winBatteryCollector) Name() string { return "batteries" }
func (winBatteryCollector) Level() int   { return levelQuick }
func (winBatteryCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		Name                     string
		DeviceID                 string
		Chemistry                uint16
		BatteryStatus            uint16
		EstimatedChargeRemaining uint16
		EstimatedRunTime         uint32
		DesignVoltage            uint32
	}
	if err := wmi.Query("SELECT Name,DeviceID,Chemistry,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,DesignVoltage FROM Win32_Battery", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		runTime := r.EstimatedRunTime
		if runTime >= 4294967295 || runTime == 71582788 {
			runTime = 0
		}
		out = append(out, schema.Record{
			"key": "battery:" + r.DeviceID, "name": r.Name, "device_id": r.DeviceID,
			"chemistry": r.Chemistry, "status": r.BatteryStatus,
			"percent_remaining": r.EstimatedChargeRemaining, "run_time_minutes": runTime,
			"voltage_mv": r.DesignVoltage,
		})
	}
	return out, nil
}

type winAntivirusCollector struct{}

func (winAntivirusCollector) Name() string { return "antivirus" }
func (winAntivirusCollector) Level() int   { return levelQuick }
func (winAntivirusCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		DisplayName            string
		InstanceGUID           string
		ProductState           uint32
		PathToSignedProductExe string
	}
	if err := wmi.QueryNamespace("SELECT DisplayName,InstanceGUID,ProductState,PathToSignedProductExe FROM AntiVirusProduct", &rows, "root\\SecurityCenter2"); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "invalid namespace") {
			return []schema.Record{}, nil
		}
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key": "av:" + r.InstanceGUID, "name": r.DisplayName, "enabled": (r.ProductState>>12)&0xF != 0,
			"product_state": strconv.FormatUint(uint64(r.ProductState), 16), "instance_guid": r.InstanceGUID,
			"product_exe": r.PathToSignedProductExe,
		})
	}
	return out, nil
}

type winServiceCollector struct{}

func (winServiceCollector) Name() string { return "services" }
func (winServiceCollector) Level() int   { return levelFull }
func (winServiceCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		Name        string
		DisplayName string
		Description string
		ServiceType string
		State       string
		StartMode   string
		StartName   string
		PathName    string
	}
	if err := wmi.Query("SELECT Name,DisplayName,Description,ServiceType,State,StartMode,StartName,PathName FROM Win32_Service", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key": "service:" + r.Name, "name": r.Name, "display_name": r.DisplayName,
			"description": r.Description, "service_type": r.ServiceType, "status": r.State,
			"start_type": r.StartMode, "user_account": r.StartName, "path": r.PathName,
		})
	}
	return out, nil
}

type winDriverCollector struct{}

func (winDriverCollector) Name() string { return "drivers" }
func (winDriverCollector) Level() int   { return levelFull }
func (winDriverCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		DeviceName         string
		DeviceClass        string
		Manufacturer       string
		DriverProviderName string
		DriverVersion      string
		DriverDate         string
		IsSigned           bool
		InfName            string
	}
	if err := wmi.Query("SELECT DeviceName,DeviceClass,Manufacturer,DriverProviderName,DriverVersion,DriverDate,IsSigned,InfName FROM Win32_PnPSignedDriver", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key": "driver:" + r.DeviceName + ":" + r.InfName, "device_name": r.DeviceName,
			"device_class": r.DeviceClass, "manufacturer": r.Manufacturer, "provider": r.DriverProviderName,
			"version": r.DriverVersion, "driver_date": r.DriverDate,
			"is_signed": r.IsSigned, "inf_name": r.InfName,
		})
	}
	return out, nil
}

type winPhysicalDiskCollector struct{}

func (winPhysicalDiskCollector) Name() string { return "physical_disks" }
func (winPhysicalDiskCollector) Level() int   { return levelFull }
func (winPhysicalDiskCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		Index            uint32
		Model            string
		Manufacturer     string
		SerialNumber     string
		Size             uint64
		InterfaceType    string
		MediaType        string
		FirmwareRevision string
		Partitions       uint32
		BytesPerSector   uint32
		Status           string
	}
	if err := wmi.Query("SELECT Index,Model,Manufacturer,SerialNumber,Size,InterfaceType,MediaType,FirmwareRevision,Partitions,BytesPerSector,Status FROM Win32_DiskDrive", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key": "disk:" + strconv.Itoa(int(r.Index)), "index": r.Index, "model": r.Model,
			"manufacturer": r.Manufacturer, "serial_number": r.SerialNumber, "size_bytes": int64(r.Size),
			"interface_type": r.InterfaceType, "media_type": r.MediaType, "firmware": r.FirmwareRevision,
			"partition_count": r.Partitions, "bytes_per_sector": r.BytesPerSector, "status": r.Status,
		})
	}
	return out, nil
}

type winListeningPortCollector struct{}

func (winListeningPortCollector) Name() string { return "listening_ports" }
func (winListeningPortCollector) Level() int   { return levelFull }
func (winListeningPortCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	output, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return nil, err
	}
	out := []schema.Record{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		if proto == "tcp" && (len(fields) < 5 || fields[3] != "LISTENING") {
			continue
		}
		local := fields[1]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		addr := local[:idx]
		port, err := strconv.Atoi(local[idx+1:])
		if err != nil || port < 1 || port >= 49152 {
			continue
		}
		family := "ipv4"
		if strings.Contains(addr, ":") {
			family = "ipv6"
		}
		pidField := fields[len(fields)-1]
		out = append(out, schema.Record{
			"key":      proto + "|" + family + "|" + addr + "|" + strconv.Itoa(port) + "|" + pidField,
			"protocol": proto, "address": addr, "port": port, "family": family, "pid": pidField,
		})
	}
	return out, nil
}

type winUSBCollector struct{}

func (winUSBCollector) Name() string { return "usb_devices" }
func (winUSBCollector) Level() int   { return levelFull }
func (winUSBCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		Name         string
		DeviceID     string
		Manufacturer string
		Status       string
		Service      string
	}
	if err := wmi.Query("SELECT Name,DeviceID,Manufacturer,Status,Service FROM Win32_PnPEntity WHERE PNPClass='USB'", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key": "usb:" + r.DeviceID, "name": r.Name, "device_id": r.DeviceID,
			"manufacturer": r.Manufacturer, "status": r.Status, "service": r.Service, "class": "USB",
		})
	}
	return out, nil
}

type winStartupCollector struct{}

func (winStartupCollector) Name() string { return "startup_items" }
func (winStartupCollector) Level() int   { return levelFull }
func (winStartupCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		Name     string
		Command  string
		Location string
		User     string
	}
	if err := wmi.Query("SELECT Name,Command,Location,User FROM Win32_StartupCommand", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key":  "startup:" + r.Name + ":" + r.Location + ":" + r.User,
			"name": r.Name, "command": r.Command, "location": r.Location, "user": r.User,
		})
	}
	return out, nil
}

type winUACCollector struct{}

func (winUACCollector) Name() string { return "uac" }
func (winUACCollector) Level() int   { return levelMinimal }
func (winUACCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	rec := schema.Record{"key": "uac"}
	if v, _, err := k.GetIntegerValue("EnableLUA"); err == nil {
		rec["enable_lua"] = v
	}
	if v, _, err := k.GetIntegerValue("ConsentPromptBehaviorAdmin"); err == nil {
		rec["consent_prompt_behavior_admin"] = v
	}
	if v, _, err := k.GetIntegerValue("PromptOnSecureDesktop"); err == nil {
		rec["prompt_on_secure_desktop"] = v
	}
	return []schema.Record{rec}, nil
}

type winFirewallCollector struct{}

func (winFirewallCollector) Name() string { return "firewall_profiles" }
func (winFirewallCollector) Level() int   { return levelMinimal }
func (winFirewallCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	profiles := []struct{ key, name string }{
		{"DomainProfile", "domain"},
		{"StandardProfile", "private"},
		{"PublicProfile", "public"},
	}
	out := []schema.Record{}
	for _, p := range profiles {
		path := `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\` + p.key
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		rec := schema.Record{"key": "firewall:" + p.name, "profile": p.name}
		if v, _, err := k.GetIntegerValue("EnableFirewall"); err == nil {
			rec["enabled"] = v == 1
		}
		if v, _, err := k.GetIntegerValue("DefaultInboundAction"); err == nil {
			rec["default_inbound"] = allowBlock(v, true)
		}
		if v, _, err := k.GetIntegerValue("DefaultOutboundAction"); err == nil {
			rec["default_outbound"] = allowBlock(v, false)
		}
		k.Close()
		out = append(out, rec)
	}
	return out, nil
}

func allowBlock(v uint64, inbound bool) string {
	if inbound {
		if v == 1 {
			return "allow"
		}
		return "block"
	}
	if v == 1 {
		return "block"
	}
	return "allow"
}

type winLoggedOnUserCollector struct{}

func (winLoggedOnUserCollector) Name() string { return "logged_on_users" }
func (winLoggedOnUserCollector) Level() int   { return levelQuick }
func (winLoggedOnUserCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var cs []struct{ UserName string }
	if err := wmi.Query("SELECT UserName FROM Win32_ComputerSystem", &cs); err != nil {
		return nil, err
	}
	if len(cs) == 0 || cs[0].UserName == "" {
		return []schema.Record{}, nil
	}
	user := cs[0].UserName
	return []schema.Record{{"key": "session:" + user, "user_name": user, "session_type": "console", "logon_time": nil, "sid": nil}}, nil
}

type winMonitorCollector struct{}

func (winMonitorCollector) Name() string { return "monitors" }
func (winMonitorCollector) Level() int   { return levelFull }
func (winMonitorCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	var rows []struct {
		DeviceID            string
		Name                string
		MonitorManufacturer string
		MonitorType         string
		ScreenWidth         uint32
		ScreenHeight        uint32
		Availability        uint16
	}
	if err := wmi.Query("SELECT DeviceID,Name,MonitorManufacturer,MonitorType,ScreenWidth,ScreenHeight,Availability FROM Win32_DesktopMonitor", &rows); err != nil {
		return nil, err
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, schema.Record{
			"key": "monitor:" + r.DeviceID, "manufacturer": r.MonitorManufacturer, "name": r.Name,
			"serial_number": nil, "product_code": r.MonitorType,
			"resolution": strconv.Itoa(int(r.ScreenWidth)) + "x" + strconv.Itoa(int(r.ScreenHeight)),
			"status":     r.Availability, "source": "cim",
		})
	}
	return out, nil
}

type winAppxCollector struct{}

func (winAppxCollector) Name() string { return "appx_packages" }
func (winAppxCollector) Level() int   { return levelFull }
func (winAppxCollector) Collect(_ context.Context, _ *Session) ([]schema.Record, error) {
	script := "Get-AppxPackage -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Version=[string]$_.Version; Publisher=$_.Publisher; PackageFullName=$_.PackageFullName; InstallLocation=$_.InstallLocation } } | ConvertTo-Json -Compress -Depth 4"
	output, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil || len(output) == 0 {
		return []schema.Record{}, nil
	}
	type appx struct {
		Name            string
		Version         string
		Publisher       string
		PackageFullName string
		InstallLocation string
	}
	var rows []appx
	if err := json.Unmarshal(output, &rows); err != nil {
		var single appx
		if err2 := json.Unmarshal(output, &single); err2 != nil {
			return []schema.Record{}, nil
		}
		rows = []appx{single}
	}
	out := make([]schema.Record, 0, len(rows))
	for _, r := range rows {
		if r.Name == "" {
			continue
		}
		out = append(out, schema.Record{
			"key": "appx:" + r.PackageFullName, "name": r.Name, "version": r.Version,
			"vendor": r.Publisher, "install_location": r.InstallLocation, "format": "appx",
			"source": "appx", "scope": "user",
		})
	}
	return out, nil
}
