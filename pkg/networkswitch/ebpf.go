package networkswitch

import (
	"fmt"

	"github.com/cilium/cilium/pkg/option"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package networkswitch -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../../ebpf/switch.c -- -I ../../ebpf/include

func xdpModeToFlag(xdpMode string) uint32 {
	switch xdpMode {
	case option.XDPModeNative:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	case option.XDPModeLinkDriver:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeLinkGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	}
	return 0
}

// attachPrograms, will attach the XDP and TC programs to the specific interface
// If will attempt to determine which type of XDP mode to use before attaching
func (port *SwitchPort) attachPrograms() error {
	if port.eBPF.ProgXdp != nil {
		mode := port.settings.XDPMode
		if mode == "" {
			mode = DEFAULT_XDP_MODE
		}

		err := netlink.LinkSetXdpFdWithFlags(port.netlink, port.eBPF.ProgXdp.FD(), int(xdpModeToFlag(mode)))
		if err != nil { //forced, todo
			fmt.Printf("Error attaching XDP program with flag: %s. Using xdpgeneric instead.", mode)
			if DEFAULT_XDP_MODE == option.XDPModeLinkGeneric {
				port.settings.XDPMode = ""
			} else {
				port.settings.XDPMode = option.XDPModeLinkGeneric
			}
			mode = option.XDPModeLinkGeneric
			err = netlink.LinkSetXdpFdWithFlags(port.netlink, port.eBPF.ProgXdp.FD(), int(xdpModeToFlag(mode)))
			if err != nil {
				return fmt.Errorf("attaching XDP program to interface %s: %w", port.iface.Name, err)
			}
		}
	}

	if port.eBPF.ProgTc != nil {
		if err := replaceQdisc(port.netlink); err != nil {
			return fmt.Errorf("replacing clsact qdisc for interface %s: %w", port.iface.Name, err)
		}

		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: port.netlink.Attrs().Index,
				Handle:    netlink.MakeHandle(0, 1),
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
				// Priority: uint16(option.Config.TCFilterPriority),
			},
			Fd:           port.eBPF.ProgTc.FD(),
			Name:         fmt.Sprintf("%s-tc-ingress-%s", PROG_NAME, port.iface.Name),
			DirectAction: true,
		}

		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("replacing tc filter: %w", err)
		}
	}

	return nil
}

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}
