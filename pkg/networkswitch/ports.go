package networkswitch

import (
	"fmt"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/ebpf"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"github.com/xlab/treeprint"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"
)

func init() {
	DEFAULT_XDP_MODE = option.XDPModeLinkDriver
}

func (settings *PortSettings) Validate() {
	if settings.Trunk {
		settings.Vlans = []uint16{}
	} else {
		allKeys := make(map[uint16]bool)
		list := []uint16{}
		for _, vlan := range settings.Vlans {
			if vlan != settings.PVID {
				_, exists := allKeys[vlan]
				if !exists {
					allKeys[vlan] = true
					list = append(list, vlan)
				}
			}
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i] < list[j] //todo- vlan priority sort order, for now numerical order
		})
		settings.Vlans = list
	}
}

func DownAll() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {
		err = DownInterface(iface.Name)
		if err != nil {
			return err
		}
	}

	/////// Close FDB Map
	mapFdb, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_fdb_xdp", nil)
	if err == nil {
		if mapFdb.IsPinned() {
			err = mapFdb.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapFdb.Close()
		if err != nil {
			return err
		}
	}

	/////// Close xdp stats
	mapStats, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_stats_xdp", nil)
	if err == nil {
		if mapStats.IsPinned() {
			err = mapStats.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapStats.Close()
		if err != nil {
			return err
		}
	}

	/////// Close Jump Map xdp
	mapJmpXdp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_jump_table_xdp", nil)
	if err == nil {
		if mapJmpXdp.IsPinned() {
			err = mapJmpXdp.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapJmpXdp.Close()
		if err != nil {
			return err
		}
	}

	/////// Close Jump Map tc
	mapJmpTc, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_jump_table_tc", nil)
	if err == nil {
		if mapJmpTc.IsPinned() {
			err = mapJmpTc.Unpin()
			if err != nil {
				return err
			}
		}
		err = mapJmpTc.Close()
		if err != nil {
			return err
		}
	}

	fmt.Printf("%s down\n", PROG_NAME)
	return nil
}

func DownInterface(ifName string) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}

	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}
	defer ethHandle.Close()

	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return err
	}

	filtersIngress, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return err
	}

	/////// TC detach
	matchedIngress := false
	for _, filt := range filtersIngress {
		attrs := filt.Attrs()
		if filt.Type() == "bpf" && attrs.Protocol == unix.ETH_P_ALL && attrs.Handle == netlink.MakeHandle(0, 1) {
			matchedIngress = true

			fmt.Printf("[%s] Setting port down... ", iface.Name)
			/////// set port down
			err = netlink.LinkSetDown(link)
			if err != nil {
				return err
			}

			err = netlink.SetPromiscOff(link)
			if err != nil {
				return err
			}

			ethHandle.Change(iface.Name, FEATURES_ENABLE)

			fmt.Printf("detaching TC... ")
			/////// TC detach
			err = netlink.FilterDel(filt)
			if err != nil {
				return err
			}
		}
	}

	/////// TC EGRESS detach
	filtersEgress, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return err
	}
	for _, filt := range filtersEgress {
		attrs := filt.Attrs()
		if matchedIngress && filt.Type() == "bpf" && attrs.Protocol == unix.ETH_P_ALL && attrs.Handle == netlink.MakeHandle(0, 1) {
			err = netlink.FilterDel(filt)
			if err != nil {
				return err
			}
		}
	}

	/////// XDP detach
	if matchedIngress {
		fmt.Printf("detaching XDP... ")
		// err = netlink.LinkSetXdpFd(link, -1)
		err = netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpModeToFlag(option.XDPModeLinkDriver)))
		if err != nil {
			return err
		}

		err = netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpModeToFlag(option.XDPModeGeneric)))
		if err != nil {
			return err
		}
		fmt.Printf("👌\n")
	}

	return nil
}

// func (bridge *BridgeGroup) Down() error {
// 	for _, port := range bridge.IfList {
// 		err := DownInterface(port.iface.Name)
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	/////// Close FDB Map
// 	mapFdb, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_fdb_xdp", nil)
// 	if err == nil {
// 		if mapFdb.IsPinned() {
// 			err = mapFdb.Unpin()
// 			if err != nil {
// 				return err
// 			}
// 		}
// 		err = mapFdb.Close()
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	/////// Close xdp stats
// 	mapStats, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_stats_xdp", nil)
// 	if err == nil {
// 		if mapStats.IsPinned() {
// 			err = mapStats.Unpin()
// 			if err != nil {
// 				return err
// 			}
// 		}
// 		err = mapStats.Close()
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	/////// Close xdp Jump Map
// 	mapJmpXdp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_jump_table_xdp", nil)
// 	if err == nil {
// 		if mapJmpXdp.IsPinned() {
// 			err = mapJmpXdp.Unpin()
// 			if err != nil {
// 				return err
// 			}
// 		}
// 		err = mapJmpXdp.Close()
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	/////// Close tc Jump Map
// 	mapJmpTc, err := ebpf.LoadPinnedMap("/sys/fs/bpf/Map_jump_table_tc", nil)
// 	if err == nil {
// 		if mapJmpTc.IsPinned() {
// 			err = mapJmpTc.Unpin()
// 			if err != nil {
// 				return err
// 			}
// 		}
// 		err = mapJmpTc.Close()
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	fmt.Printf("%s down\n", PROG_NAME)
// 	return nil
// }

func (group *BridgeGroup) GetPortByName(name string) (*SwitchPort, error) {
	port, exists := group.IfMap[name]
	if !exists {
		return nil, fmt.Errorf("Port doesn't exist in bridge (name: %s)", name)
	}
	return port, nil
}

func (group *BridgeGroup) GetPortByIndex(index int) (*SwitchPort, error) {
	port, exists := group.IfMapByIndex[uint16(index)]
	if !exists {
		return nil, fmt.Errorf("Port doesn't exist in bridge (index: %d)", index)
	}
	return port, nil
}

func (group *BridgeGroup) GetPortList() []*SwitchPort {
	return group.IfList
}

func (group *BridgeGroup) BuildPortList() []*SwitchPort {
	list := maps.Values(group.IfMap)
	sort.Slice(list, func(i, j int) bool {
		return list[i].iface.Index < list[j].iface.Index
	})
	return list
}

func (group *BridgeGroup) PrettyPrint() string {
	tree := treeprint.NewWithRoot(PROG_NAME)

	for _, port := range group.GetPortList() {
		mode := port.settings.XDPMode
		if mode == "" {
			mode = DEFAULT_XDP_MODE
		}

		treePortName := tree.AddBranch(fmt.Sprintf("%s", port.iface.Name))
		treePortName.AddNode(fmt.Sprintf("driver: %s (%s)", port.driverName, mode))
		if port.settings.Transparent {
			treePortName.AddNode("transparent: true")
		}

		treePortVlans := treePortName.AddBranch("VLANs")
		treePortVlans.AddNode(fmt.Sprintf("untagged: %d", port.settings.PVID))

		if port.settings.Trunk {
			treePortVlans.AddNode("tagged: trunk")
		} else if len(port.settings.Vlans) > 0 {
			switch len(port.settings.Vlans) {
			case 0:
				_ = 0
			case 1:
				treePortVlans.AddNode(fmt.Sprintf("tagged: %d", port.settings.Vlans[0]))
			default:
				treePortTagged := treePortVlans.AddBranch("tagged:")
				for _, vlan := range port.settings.Vlans {
					treePortTagged.AddNode(fmt.Sprintf("%d", vlan))
				}
			}
		}

	}

	return tree.String()
}

func (group *BridgeGroup) AddPort(ifName string, settings PortSettings) error {
	var err error
	name := ifName

	ifReference, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}

	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}

	nl, err := netlink.LinkByName(ifReference.Name)
	if err != nil {
		return err
	}

	driverName, err := ethHandle.DriverName(ifReference.Name)
	if err != nil {
		return err
	}

	trafficByCore, err := lru.New[int, *StatsTraffic](runtime.NumCPU())
	if err != nil {
		return err
	}

	trafficByKey, err := lru.New[StatsTrafficKey, *StatsTraffic](65536)
	if err != nil {
		return err
	}

	trafficBySrcIPv4, err := lru.New[uint32, *StatsTraffic](65536)
	if err != nil {
		return err
	}

	trafficByDstIPv4, err := lru.New[uint32, *StatsTraffic](65536)
	if err != nil {
		return err
	}

	trafficByVLAN, err := lru.New[uint16, *StatsTraffic](4094)
	if err != nil {
		return err
	}

	trafficByProtoL2, err := lru.New[uint16, *StatsTraffic](256)
	if err != nil {
		return err
	}

	trafficByProtoL3, err := lru.New[uint16, *StatsTraffic](256)
	if err != nil {
		return err
	}

	trafficByDstIface, err := lru.New[uint16, *StatsTraffic](MAX_IFACES)
	if err != nil {
		return err
	}

	port := SwitchPort{
		iface:         ifReference,
		settings:      settings,
		driverName:    driverName,
		speed:         0,
		ethtoolHandle: ethHandle,
		ethtoolCmd:    &ethtool.EthtoolCmd{},
		netlink:       nl,
		// Tap:           waterInterface, //todo
		Stats: portStats{},
		Traffic: TrafficObserver{ //todo -move to port
			mutex:             sync.RWMutex{},
			trafficTotal:      NewStatsTraffic(),
			trafficByCore:     trafficByCore,
			trafficByKey:      trafficByKey,
			trafficBySrcIPv4:  trafficBySrcIPv4,
			trafficByDstIPv4:  trafficByDstIPv4,
			trafficByVLAN:     trafficByVLAN,
			trafficByProtoL2:  trafficByProtoL2,
			trafficByProtoL3:  trafficByProtoL3,
			trafficByDstIface: trafficByDstIface,
		},
	}
	port.Stats.PortName = ifReference.Name

	group.IfMap[ifName] = &port
	group.IfMapByIndex[uint16(ifReference.Index)] = &port

	return nil
}

func (bridge *BridgeGroup) Up() error {
	return bridge.allUpEbpf()
}

func (bridge *BridgeGroup) allUpEbpf() error {
	for _, port := range bridge.IfList {
		err := port.upEbpf(bridge.IfList)
		if err != nil {
			return err
		}
	}
	return nil
}

// func (group *BridgeGroup) allDownEbpf() {
// 	for _, port := range group.IfMap {
// 		err := port.downEbpf()
// 		if err != nil {
// 			fmt.Println("ERROR: " + err.Error())
// 		}
// 	}
// }

func (port *SwitchPort) upEbpf(ifList []*SwitchPort) error {
	fmt.Println("Setting promisc")
	err := netlink.SetPromiscOn(port.netlink)
	if err != nil {
		return err
	}
	fmt.Println("Setting ethtool features")

	err = port.ethtoolHandle.Change(port.iface.Name, FEATURES_DISABLE)
	if err != nil {
		return err
	}

	fmt.Println("Setting link")
	err = netlink.LinkSetUp(port.netlink)
	if err != nil {
		return err
	}

	fmt.Println("Getting eth speed")
	port.speed, err = port.ethtoolHandle.CmdGet(port.ethtoolCmd, port.iface.Name)
	if err != nil {
		return err
	}
	if port.speed == 4294967295 { //unknown speed
		port.speed = 0
	}

	fmt.Println("loading bpf")
	port.eBPFSpec, err = loadBpf()
	if err != nil {
		return err
	}

	port.eBPFSpec.Maps["Map_fdb_xdp"].Pinning = ebpf.PinByName
	port.eBPFSpec.Maps["Map_stats_xdp"].Pinning = ebpf.PinByName
	port.eBPFSpec.Maps["Map_jump_table_xdp"].Pinning = ebpf.PinByName
	port.eBPFSpec.Maps["Map_jump_table_tc"].Pinning = ebpf.PinByName

	var portCfgVlanBitmask [64]uint64
	if port.settings.Trunk {
		portCfgVlanBitmask = bitmaskAllVlans64([]uint16{port.settings.PVID})
	} else {
		portCfgVlanBitmask = bitmaskVlanList64(port.settings.Vlans)
	}

	ingressFiltering := uint16(0)
	if port.settings.IngressFiltering {
		ingressFiltering = 1
	}

	macBytes := [6]byte{}
	copy(macBytes[:], port.iface.HardwareAddr[:6])
	transparent := uint16(0)
	if port.settings.Transparent {
		transparent = 1
	}
	hookDrop := uint16(0)
	if port.settings.HookDrop != "" {
		hookDrop = 1
	}
	hookEgress := uint16(0)
	if port.settings.HookEgress != "" {
		hookEgress = 1
	}
	portCfg := bpfPortCfg{
		IfIndex:          uint16(port.iface.Index),
		Pvid:             port.settings.PVID,
		VlanBitmask:      portCfgVlanBitmask,
		Mac:              macBytes,
		Transparent:      transparent,
		IngressFiltering: ingressFiltering,
		HookDrop:         hookDrop,
		HookEgress:       hookEgress,
		Tap:              uint16(1),
	}

	portCfgListByIdx := [MAX_IFACES]bpfPortCfg{}
	portIdxList := [MAX_IFACES]uint8{}
	for idx, p := range ifList {
		var pCfgVlanBitmask [64]uint64
		if p.settings.Trunk {
			pCfgVlanBitmask = bitmaskAllVlans64([]uint16{p.settings.PVID})
		} else {
			pCfgVlanBitmask = bitmaskVlanList64(p.settings.Vlans)
		}

		ingressFiltering = uint16(0)
		if p.settings.IngressFiltering {
			ingressFiltering = 1
		}

		macBytes = [6]byte{}
		copy(macBytes[:], p.iface.HardwareAddr[:6])

		transparent = 0
		if p.settings.Transparent {
			transparent = 1
		}

		hookDrop = 0
		if p.settings.HookDrop != "" {
			hookDrop = 1
		}
		hookEgress = 0
		if p.settings.HookEgress != "" {
			hookEgress = 1
		}

		fmt.Printf("index: %d\n", p.iface.Index)
		portCfgListByIdx[p.iface.Index] = bpfPortCfg{
			IfIndex:          uint16(p.iface.Index),
			Pvid:             p.settings.PVID,
			VlanBitmask:      pCfgVlanBitmask,
			Mac:              macBytes,
			Transparent:      transparent,
			IngressFiltering: ingressFiltering,
			HookDrop:         hookDrop,
			HookEgress:       hookEgress,
			Tap:              uint16(0),
		}

		portIdxList[idx] = uint8(p.iface.Index)
	}

	enableStats := uint8(0)
	if STATS_ENABLED {
		enableStats = 1
	}
	err = port.eBPFSpec.RewriteConstants(map[string]interface{}{
		"PORT_CFG":         portCfg,
		"PORT_COUNT":       uint8(len(ifList)),
		"PORTS_CFG_BY_IDX": portCfgListByIdx,

		"PORTS_IDX":     portIdxList,
		"STATS_ENABLED": enableStats,
	})
	if err != nil {
		panic(err)
	}

	collectionOpts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// The base path to pin maps in if requested via PinByName.
			// Existing maps will be re-used if they are compatible, otherwise an
			// error is returned.
			// PinPath: "/sys/fs/bpf/xdp_switch",
			PinPath: "/sys/fs/bpf/",
			// LoadPinOptions: ebpf.LoadPinOptions{},
		},
		// Programs: ProgramOptions,
		// MapReplacements: map[string]*ebpf.Map,
	}

	if err := port.eBPFSpec.LoadAndAssign(&port.eBPF, &collectionOpts); err != nil {
		panic(err)
	}

	// This section aligns all of the tail calls with the maps so that they're called
	// correctly within the eBPF program
	port.eBPF.MapJumpTableTc.Put(int32(1), int32(port.eBPF.TailCall1.FD()))  // HANDLE_UNTAGGED
	port.eBPF.MapJumpTableTc.Put(int32(2), int32(port.eBPF.TailCall2.FD()))  // HANDLE_TAGGED
	port.eBPF.MapJumpTableTc.Put(int32(3), int32(port.eBPF.TailCall1B.FD())) // HANDLE_UNTAGGED_B
	port.eBPF.MapJumpTableTc.Put(int32(4), int32(port.eBPF.TailCall2B.FD())) // HANDLE_TAGGED_B
	port.eBPF.MapJumpTableTc.Put(int32(5), int32(port.eBPF.HookDropTc.FD()))
	port.eBPF.MapJumpTableTc.Put(int32(6), int32(port.eBPF.HookEgressTc.FD()))

	port.eBPF.MapJumpTableXdp.Put(int32(1), int32(port.eBPF.HookDropXdp.FD()))
	port.eBPF.MapJumpTableXdp.Put(int32(2), int32(port.eBPF.HookEgressXdp.FD()))

	port.Stats.UpTimestamp = time.Now()

	err = port.attachPrograms()
	if err != nil {
		panic(err)
	}

	return nil
}
