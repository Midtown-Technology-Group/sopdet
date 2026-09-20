package collect

import "strings"

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
