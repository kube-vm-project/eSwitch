package networkswitch

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
)

const MAX_IFACES = 255 // (was 80, this might break something)
const TRAFFIC_KEY_SIZE = 16
const STATS_ENABLED = false

const (
	HANDLE_UNTAGGED_TAIL_CALL   = 1
	HANDLE_TAGGED_TAIL_CALL     = 2
	HANDLE_UNTAGGED_TAIL_CALL_B = 3
	HANDLE_TAGGED_TAIL_CALL_B   = 4

	HOOK_DROP_TC   = 5
	HOOK_EGRESS_TC = 6
)

var FEATURES_ENABLE = map[string]bool{
	// "rx-gro":                  true,
	"rx-vlan-hw-parse":  true,
	"tx-vlan-hw-insert": true,
	// "rx-hashing":              true,
	// "tx-tcp-segmentation":     true,
	// "tx-tcp-ecn-segmentation": true,
	// "tx-tcp6-segmentation":    true,
	// "generic-receive-offload": true,
}
var FEATURES_DISABLE = map[string]bool{
	// "rx-gro":                  false,
	"rx-vlan-hw-parse":  false,
	"tx-vlan-hw-insert": false,
	// "rx-hashing":              false,
	// "tx-tcp-segmentation":     false,
	// "tx-tcp-ecn-segmentation": false,
	// "tx-tcp6-segmentation":    false,
	// "generic-receive-offload": false,
}

var PROG_NAME string
var DEFAULT_XDP_MODE string

type BridgeGroup struct {
	IfMap        map[string]*SwitchPort
	IfMapByIndex map[uint16]*SwitchPort

	IfList []*SwitchPort
}

type SwitchPort struct {
	driverName    string
	speed         uint32
	settings      PortSettings
	iface         *net.Interface
	netlink       netlink.Link
	ethtoolHandle *ethtool.Ethtool
	ethtoolCmd    *ethtool.EthtoolCmd
	eBPFSpec      *ebpf.CollectionSpec
	eBPF          bpfObjects
	// Tap           *water.Interface //todo
	Stats   portStats
	Traffic TrafficObserver
}

type PortSettings struct {
	Tap              bool     `json:"tap,omitempty" yaml:"tap,omitempty"` //todo
	PVID             uint16   `json:"pvid,omitempty" yaml:"pvid,omitempty"`
	Vlans            []uint16 `json:"vlans,omitempty" yaml:"vlans,omitempty"`
	Trunk            bool     `json:"trunk,omitempty" yaml:"trunk,omitempty"`
	XDPMode          string   `json:"xdpMode,omitempty" yaml:"xdpMode,omitempty"`
	Transparent      bool     `json:"transparent,omitempty" yaml:"transparent,omitempty"`
	HookDrop         string   `json:"hookDrop,omitempty" yaml:"hookDrop,omitempty"`
	HookEgress       string   `json:"hookEgress,omitempty" yaml:"hookEgress,omitempty"`
	IngressFiltering bool     `json:"-" yaml:"-"`
	DontDown         bool
}
