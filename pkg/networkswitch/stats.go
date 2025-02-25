package networkswitch

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

type StatsXDP struct {
	// mutex             sync.RWMutex
	RxDroppedBytes      uint64 `json:"RxDroppedBytes" yaml:"RxDroppedBytes"`
	RxDroppedPackets    uint64 `json:"RxDroppedPackets" yaml:"RxDroppedPackets"`
	RxPassedBytes       uint64 `json:"RxPassedBytes" yaml:"RxPassedBytes"`
	RxPassedPackets     uint64 `json:"RxPassedPackets" yaml:"RxPassedPackets"`
	RxRedirectedBytes   uint64 `json:"RxRedirectedBytes" yaml:"RxRedirectedBytes"`
	RxRedirectedPackets uint64 `json:"RxRedirectedPackets" yaml:"RxRedirectedPackets"`
	RxLastTimestamp     uint64 `json:"RxLastTimestamp" yaml:"RxLastTimestamp"`

	TxRedirectedBytes   uint64 `json:"TxRedirectedBytes" yaml:"TxRedirectedBytes"`
	TxRedirectedPackets uint64 `json:"TxRedirectedPackets" yaml:"TxRedirectedPackets"`
	TxLastTimestamp     uint64 `json:"TxLastTimestamp" yaml:"TxLastTimestamp"`
}

type StatsTrafficKey struct {
	SrcIPv4       uint32 `json:"SrcIPv4" yaml:"SrcIPv4"`
	DstIPv4       uint32 `json:"DstIPv4" yaml:"DstIPv4"`
	Vlan          uint16 `json:"Vlan" yaml:"Vlan"`
	ProtoL2       uint16 `json:"ProtoL2" yaml:"ProtoL2"`
	ProtoL3       uint16 `json:"ProtoL3" yaml:"ProtoL3"`
	TargetIfIndex uint16 `json:"TargetIfIndex" yaml:"TargetIfIndex"`
}

type LatestPacketInfo struct {
	Timestamp uint64 `json:"Timestamp" yaml:"Timestamp"`
	Tagged    uint8  `json:"Tagged" yaml:"Tagged"`
	Size      uint16 `json:"Size" yaml:"Size"`
}

func NewStatsTraffic() *StatsTraffic {
	return &StatsTraffic{
		mutex: sync.RWMutex{},
		LatestPacket: LatestPacketInfo{
			Timestamp: 0,
			Tagged:    0,
			Size:      0,
		},

		RxDroppedBytes:      0,
		RxDroppedPackets:    0,
		RxPassedBytes:       0,
		RxPassedPackets:     0,
		RxRedirectedBytes:   0,
		RxRedirectedPackets: 0,
	}
}

func UnmarshallStatsTraffic(trafficBytes []byte) StatsTraffic {
	return StatsTraffic{
		mutex: sync.RWMutex{},
		LatestPacket: LatestPacketInfo{
			Timestamp: binary.LittleEndian.Uint64(trafficBytes[:8]),
			Tagged:    trafficBytes[8],
			Size:      binary.BigEndian.Uint16(trafficBytes[9:11]),
		},

		RxDroppedBytes:      binary.LittleEndian.Uint64(trafficBytes[11:19]),
		RxDroppedPackets:    binary.LittleEndian.Uint64(trafficBytes[19:27]),
		RxPassedBytes:       binary.LittleEndian.Uint64(trafficBytes[27:35]),
		RxPassedPackets:     binary.LittleEndian.Uint64(trafficBytes[35:43]),
		RxRedirectedBytes:   binary.LittleEndian.Uint64(trafficBytes[43:51]),
		RxRedirectedPackets: binary.LittleEndian.Uint64(trafficBytes[51:59]),
	}
}

func (stats *StatsTraffic) Add(statsToAdd *StatsTraffic) {
	stats.RxDroppedBytes += statsToAdd.RxDroppedBytes
	stats.RxDroppedPackets += statsToAdd.RxDroppedPackets
	stats.RxPassedBytes += statsToAdd.RxPassedBytes
	stats.RxPassedPackets += statsToAdd.RxPassedPackets
	stats.RxRedirectedBytes += statsToAdd.RxRedirectedBytes
	stats.RxRedirectedPackets += statsToAdd.RxRedirectedPackets
	if statsToAdd.LatestPacket.Timestamp > stats.LatestPacket.Timestamp {
		stats.LatestPacket = statsToAdd.LatestPacket
	}
}

func (stats *StatsTraffic) Sub(statsToSubtract *StatsTraffic) *StatsTraffic {
	ret := StatsTraffic{
		LatestPacket:        stats.LatestPacket,
		RxDroppedBytes:      stats.RxDroppedBytes - statsToSubtract.RxDroppedBytes,
		RxDroppedPackets:    stats.RxDroppedPackets - statsToSubtract.RxDroppedPackets,
		RxPassedBytes:       stats.RxPassedBytes - statsToSubtract.RxPassedBytes,
		RxPassedPackets:     stats.RxPassedPackets - statsToSubtract.RxPassedPackets,
		RxRedirectedBytes:   stats.RxRedirectedBytes - statsToSubtract.RxRedirectedBytes,
		RxRedirectedPackets: stats.RxRedirectedPackets - statsToSubtract.RxRedirectedPackets,
	}
	return &ret
}

type StatsTraffic struct {
	mutex        sync.RWMutex
	LatestPacket LatestPacketInfo `json:"LatestPacket" yaml:"LatestPacket"`

	RxDroppedBytes      uint64 `json:"RxDroppedBytes" yaml:"RxDroppedBytes"`
	RxDroppedPackets    uint64 `json:"RxDroppedPackets" yaml:"RxDroppedPackets"`
	RxPassedBytes       uint64 `json:"RxPassedBytes" yaml:"RxPassedBytes"`
	RxPassedPackets     uint64 `json:"RxPassedPackets" yaml:"RxPassedPackets"`
	RxRedirectedBytes   uint64 `json:"RxRedirectedBytes" yaml:"RxRedirectedBytes"`
	RxRedirectedPackets uint64 `json:"RxRedirectedPackets" yaml:"RxRedirectedPackets"`
}

type TrafficObserver struct {
	mutex             sync.RWMutex
	trafficTotal      *StatsTraffic
	trafficByCore     *lru.Cache[int, *StatsTraffic]
	trafficByKey      *lru.Cache[StatsTrafficKey, *StatsTraffic]
	trafficBySrcIPv4  *lru.Cache[uint32, *StatsTraffic]
	trafficByDstIPv4  *lru.Cache[uint32, *StatsTraffic]
	trafficByVLAN     *lru.Cache[uint16, *StatsTraffic]
	trafficByProtoL2  *lru.Cache[uint16, *StatsTraffic]
	trafficByProtoL3  *lru.Cache[uint16, *StatsTraffic]
	trafficByDstIface *lru.Cache[uint16, *StatsTraffic]
}

type portStats struct {
	mutex           sync.RWMutex
	PortName        string     `json:"PortName" yaml:"PortName"`
	XdpStats        StatsXDP   `json:"XdpStats" yaml:"XdpStats"`
	XdpStatsPerCore []StatsXDP `json:"XdpStatsPerCore" yaml:"XdpStatsPerCore"`
	xdpStatsHistory list.List
	UpTimestamp     time.Time `json:"UpTimestamp" yaml:"UpTimestamp"`
	UpdatedAt       time.Time `json:"UpdatedAt" yaml:"UpdatedAt"`
	RxRate          uint64    `json:"RxRate" yaml:"RxRate"` //rate in bytes per second
	RxPackets       uint64    `json:"RxPackets" yaml:"RxPackets"`
	RxBytes         uint64    `json:"RxBytes" yaml:"RxBytes"`
	TxRate          uint64    `json:"TxRate" yaml:"TxRate"` //rate in bytes per second
	TxPackets       uint64    `json:"TxPackets" yaml:"TxPackets"`
	TxBytes         uint64    `json:"TxBytes" yaml:"TxBytes"`

	PortTraffic           StatsTraffic
	PortTrafficByCore     map[uint32]StatsTraffic
	PortTrafficByKey      map[StatsTrafficKey]StatsTraffic
	PortTrafficBySrcIPv4  map[uint32]StatsTraffic
	PortTrafficByDstIPv4  map[uint32]StatsTraffic
	PortTrafficByVLAN     map[uint16]StatsTraffic
	PortTrafficByProtoL2  map[uint16]StatsTraffic
	PortTrafficByProtoL3  map[uint16]StatsTraffic
	PortTrafficByDstIface map[uint16]StatsTraffic
	PortTrafficMutex      sync.RWMutex
}

func (bridge *BridgeGroup) getStats() []*portStats {
	var list []*portStats
	for _, port := range bridge.IfList {
		list = append(list, &port.Stats)
	}
	return list
}

type IPRecord struct {
	IP        string       `json:"ip" yaml:"ip" maxminddb:"ip"`
	RDNS      string       `json:"rdns" yaml:"rdns" maxminddb:"rdns"`
	Continent string       `json:"continent" yaml:"continent" maxminddb:"continent"`
	Country   string       `json:"country" yaml:"country" maxminddb:"country"`
	City      string       `json:"city" yaml:"city" maxminddb:"city"`
	Lat       float32      `json:"lat" yaml:"lat" maxminddb:"lat"`
	Lng       float32      `json:"lng" yaml:"lng" maxminddb:"lng"`
	Traffic   StatsTraffic `json:"traffic,omitempty" yaml:"traffic,omitempty"`
	PrevHop   *IPRecord    `json:"prevHop,omitempty" yaml:"prevHop,omitempty"`
}

func (port *SwitchPort) refreshStats(countLocal, traceroute bool) {

	iter := port.eBPF.MapStatsTraffic.Iterate()
	var keyBytes [TRAFFIC_KEY_SIZE]byte
	seen := make(map[[TRAFFIC_KEY_SIZE]byte]struct{})
	cpuVals := make([][]byte, runtime.NumCPU())
	trafficTotalPort := NewStatsTraffic()
	for iter.Next(&keyBytes, &cpuVals) { // grab array of per-cpu stats for this key on this port
		_, exists := seen[keyBytes]
		if exists {
			continue // skip if already seen
		}
		seen[keyBytes] = struct{}{}

		key := StatsTrafficKey{
			SrcIPv4:       binary.BigEndian.Uint32(keyBytes[:4]),
			DstIPv4:       binary.BigEndian.Uint32(keyBytes[4:8]),
			Vlan:          binary.LittleEndian.Uint16(keyBytes[8:10]),
			ProtoL2:       binary.LittleEndian.Uint16(keyBytes[10:12]),
			ProtoL3:       binary.LittleEndian.Uint16(keyBytes[12:14]),
			TargetIfIndex: binary.LittleEndian.Uint16(keyBytes[14:16]),
		}

		srcIp := int2ip(key.SrcIPv4)
		dstIp := int2ip(key.DstIPv4)

		if srcIp.IsUnspecified() || dstIp.IsUnspecified() {
			continue
		}

		if !countLocal && srcIp.IsPrivate() {
			continue
		}
		trafficTotalKey := NewStatsTraffic()

		newTrafficOnKey := false
		for cpuIdx, cpuValBytes := range cpuVals { // iterate array of per-cpu stats for this key on this port
			timestamp := binary.LittleEndian.Uint64(cpuValBytes[:8])
			if timestamp == 0 {
				continue
			}

			cpuTraffic := UnmarshallStatsTraffic(cpuValBytes)
			trafficTotalKey.Add(&cpuTraffic)

			prevByCore, prevByCoreExists := port.Traffic.trafficByCore.Peek(cpuIdx)
			if !prevByCoreExists || timestamp > prevByCore.LatestPacket.Timestamp {
				port.Traffic.trafficByCore.Add(cpuIdx, &cpuTraffic)
				newTrafficOnKey = true
			}

		}
		trafficTotalPort.Add(trafficTotalKey)

		if newTrafficOnKey {
			var trafficDiff *StatsTraffic
			prev, exists, _ := port.Traffic.trafficByKey.PeekOrAdd(key, trafficTotalKey)
			if !exists {
				trafficStats := NewStatsTraffic()
				prev = trafficStats
				trafficDiff = trafficTotalKey
			} else {
				port.Traffic.trafficByKey.Add(key, trafficTotalKey)
				trafficDiff = trafficTotalKey.Sub(prev)
			}

			if key.TargetIfIndex != uint16(port.iface.Index) {

				prev, exists, _ = port.Traffic.trafficByDstIface.PeekOrAdd(key.TargetIfIndex, trafficDiff)
				if exists {
					prev.Add(trafficDiff)
					port.Traffic.trafficByDstIface.Add(key.TargetIfIndex, prev)
				}
			}

			prev, exists, _ = port.Traffic.trafficBySrcIPv4.PeekOrAdd(key.SrcIPv4, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficBySrcIPv4.Add(key.SrcIPv4, prev) //todo - remove this and add mutex to StatsTraffic?
			}

			prev, exists, _ = port.Traffic.trafficByDstIPv4.PeekOrAdd(key.DstIPv4, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficByDstIPv4.Add(key.DstIPv4, prev)
			}

			prev, exists, _ = port.Traffic.trafficByVLAN.PeekOrAdd(key.Vlan, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficByVLAN.Add(key.Vlan, prev)
			}

			prev, exists, _ = port.Traffic.trafficByProtoL2.PeekOrAdd(key.ProtoL2, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficByProtoL2.Add(key.ProtoL2, prev)
			}

			prev, exists, _ = port.Traffic.trafficByProtoL3.PeekOrAdd(key.ProtoL3, trafficDiff)
			if exists {
				prev.Add(trafficDiff)
				port.Traffic.trafficByProtoL3.Add(key.ProtoL3, prev)
			}
		}
	}

	port.Traffic.mutex.Lock()
	port.Traffic.trafficTotal = trafficTotalPort
	port.Traffic.mutex.Unlock()
	return
}

func (bridge *BridgeGroup) refreshStats() {
	var wg sync.WaitGroup
	for _, port := range bridge.IfList {
		wg.Add(1)
		go func(port *SwitchPort) {
			defer wg.Done()

			portTraffic := new(StatsTraffic)
			portTraffic.LatestPacket.Timestamp = 1

			iter := port.eBPF.MapStatsTraffic.Iterate()

			var keyBytes [TRAFFIC_KEY_SIZE]byte

			seen := make(map[[TRAFFIC_KEY_SIZE]byte]struct{})

			cpuVals := make([][]byte, runtime.NumCPU())

			for iter.Next(&keyBytes, &cpuVals) { //cpus array

				_, exists := seen[keyBytes]
				if exists {
					continue
				}
				seen[keyBytes] = struct{}{}

				key := StatsTrafficKey{
					SrcIPv4:       binary.BigEndian.Uint32(keyBytes[:4]),
					DstIPv4:       binary.BigEndian.Uint32(keyBytes[4:8]),
					Vlan:          binary.LittleEndian.Uint16(keyBytes[8:10]),
					ProtoL2:       binary.LittleEndian.Uint16(keyBytes[10:12]),
					ProtoL3:       binary.LittleEndian.Uint16(keyBytes[12:14]),
					TargetIfIndex: binary.LittleEndian.Uint16(keyBytes[14:16]),
				}
				srcIP := int2ip(key.SrcIPv4)
				fmt.Println(srcIP.String(), key.Vlan)

				for cpuIdx, cpuValBytes := range cpuVals { //per cpu val
					_ = cpuIdx

					Timestamp := binary.LittleEndian.Uint64(cpuValBytes[:8])
					if Timestamp > portTraffic.LatestPacket.Timestamp {
						portTraffic = &StatsTraffic{
							mutex: sync.RWMutex{},
							LatestPacket: LatestPacketInfo{
								Timestamp: Timestamp,
								Tagged:    cpuValBytes[8],
								Size:      binary.BigEndian.Uint16(cpuValBytes[9:11]),
							},

							RxDroppedBytes:      binary.LittleEndian.Uint64(cpuValBytes[11:19]),
							RxDroppedPackets:    binary.LittleEndian.Uint64(cpuValBytes[19:27]),
							RxPassedBytes:       binary.LittleEndian.Uint64(cpuValBytes[27:35]),
							RxPassedPackets:     binary.LittleEndian.Uint64(cpuValBytes[35:43]),
							RxRedirectedBytes:   binary.LittleEndian.Uint64(cpuValBytes[43:51]),
							RxRedirectedPackets: binary.LittleEndian.Uint64(cpuValBytes[51:59]),
						}
					}
				}

			}

		}(port)
	}

	wg.Wait()
	return
}

func (bridge *BridgeGroup) updateStats() error {
	for _, port := range bridge.IfList {
		stats := make([]StatsXDP, MAX_IFACES)
		tsStart := time.Now()
		err := port.eBPF.MapStatsXdp.Lookup(uint32(port.iface.Index), &stats)
		if err != nil {
			return err
		}
		ttlStats := StatsXDP{}
		for _, coreStats := range stats {
			ttlStats.RxDroppedBytes += coreStats.RxDroppedBytes
			ttlStats.RxDroppedPackets += coreStats.RxDroppedPackets
			ttlStats.RxPassedBytes += coreStats.RxPassedBytes
			ttlStats.RxPassedPackets += coreStats.RxPassedPackets
			ttlStats.RxRedirectedBytes += coreStats.RxRedirectedBytes
			ttlStats.RxRedirectedPackets += coreStats.RxRedirectedPackets
			if coreStats.RxLastTimestamp > ttlStats.RxLastTimestamp {
				ttlStats.RxLastTimestamp = coreStats.RxLastTimestamp
			}

			ttlStats.TxRedirectedBytes += coreStats.TxRedirectedBytes
			ttlStats.TxRedirectedPackets += coreStats.TxRedirectedPackets
			if coreStats.TxLastTimestamp > ttlStats.TxLastTimestamp {
				ttlStats.TxLastTimestamp = coreStats.TxLastTimestamp
			}
		}
		port.Stats.mutex.Lock()
		port.Stats.RxPackets = ttlStats.RxPassedPackets + ttlStats.RxDroppedPackets + ttlStats.RxRedirectedPackets
		port.Stats.RxBytes = ttlStats.RxPassedBytes + ttlStats.RxDroppedBytes + ttlStats.RxRedirectedBytes
		port.Stats.TxPackets = ttlStats.TxRedirectedPackets
		port.Stats.TxBytes = ttlStats.TxRedirectedBytes
		var diffRxBytes, diffTxBytes uint64
		if port.Stats.RxBytes == 0 {
			diffRxBytes = port.Stats.XdpStats.RxPassedBytes + port.Stats.XdpStats.RxDroppedBytes + port.Stats.XdpStats.RxRedirectedBytes
		} else {
			diffRxBytes = port.Stats.RxBytes - (port.Stats.XdpStats.RxPassedBytes + port.Stats.XdpStats.RxDroppedBytes + port.Stats.XdpStats.RxRedirectedBytes)
		}
		if port.Stats.TxBytes == 0 {
			diffTxBytes = port.Stats.XdpStats.TxRedirectedBytes
		} else {
			diffTxBytes = port.Stats.TxBytes - port.Stats.XdpStats.TxRedirectedBytes
		}
		diffNanoSecs := tsStart.UnixNano() - port.Stats.UpdatedAt.UnixNano()
		port.Stats.UpdatedAt = tsStart
		mult := 1000000000 / float64(diffNanoSecs)
		port.Stats.RxRate = uint64(float64(diffRxBytes) * mult)
		port.Stats.TxRate = uint64(float64(diffTxBytes) * mult)
		port.Stats.XdpStatsPerCore = stats
		port.Stats.XdpStats = ttlStats
		port.Stats.xdpStatsHistory.PushBack(port.Stats.XdpStats)
		if port.Stats.xdpStatsHistory.Len() >= 100000 {
			_ = port.Stats.xdpStatsHistory.Remove(port.Stats.xdpStatsHistory.Front())
		}
		port.Stats.mutex.Unlock()
	}
	return nil
}
