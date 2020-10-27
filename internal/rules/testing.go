package rules

import (
	"fmt"
	"os"
	"path"

	"github.com/bonjourmalware/pinknoise/internal/events"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	assetsBasePath string
)

func init() {
	gopath := os.Getenv("GOPATH")
	assetsBasePath = path.Join(gopath, "src/github.com/bonjourmalware/pinknoise/tests")
}

func ReadRawTCPPacketsFromPcap(pcapfile string) ([]gopacket.Packet, error) {
	var packets []gopacket.Packet
	_, rawPackets, err := ReadPacketsFromPcap(pcapfile, layers.IPProtocolTCP, true)
	if err != nil {
		return nil, err
	}

	for _, val := range rawPackets {
		packets = append(packets, val.(gopacket.Packet))
	}
	return packets, nil
}

func ReadPacketsFromPcap(pcapfile string, filter layers.IPProtocol, raw bool) ([]events.Event, []gopacket.Packet, error) {
	var Events []events.Event
	var rawPackets []gopacket.Packet
	var ret []events.Event
	var rawRet []gopacket.Packet
	pcapfilePath := MakeAssetFullPath(pcapfile)

	f, err := os.Open(pcapfilePath)
	if err != nil {
		return []events.Event{}, []gopacket.Packet{}, err
	}
	handle, err := pcap.OpenOfflineFile(f)
	if err != nil {
		return []events.Event{}, []gopacket.Packet{}, err
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()

loop:
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			if packet == nil {
				break loop
			}
		}

		if _, ok := packet.NetworkLayer().(*layers.IPv4); ok {
			if packet.NetworkLayer().(*layers.IPv4).Protocol == filter {
				if raw {
					rawPackets = append(rawPackets, packet)
				} else {
					switch filter {
					case layers.IPProtocolICMPv4:
						ev, err := events.NewICMPv4Event(packet)
						if err != nil {
							return []events.Event{}, []gopacket.Packet{}, err
						}

						Events = append(Events, ev)

					case layers.IPProtocolUDP:
						ev, err := events.NewUDPEvent(packet)
						if err != nil {
							return []events.Event{}, []gopacket.Packet{}, err
						}

						Events = append(Events, ev)

					case layers.IPProtocolTCP:
						ev, err := events.NewTCPEvent(packet)
						if err != nil {
							return []events.Event{}, []gopacket.Packet{}, err
						}

						Events = append(Events, ev)

					default:
						continue loop
					}
				}
			}
		} else if _, ok := packet.NetworkLayer().(*layers.IPv6); ok {
			if packet.NetworkLayer().(*layers.IPv6).NextHeader == filter {
				switch filter {
				case layers.IPProtocolICMPv6:
					ev, err := events.NewICMPv6Event(packet)
					if err != nil {
						return []events.Event{}, []gopacket.Packet{}, err
					}

					Events = append(Events, ev)

				default:
					continue loop
				}
			}
		}
	}

	// I'm so lazy
	if raw {
		rawRet = make([]gopacket.Packet, len(rawPackets))
		for key, val := range rawPackets {
			rawRet[key] = val
		}
	}

	ret = make([]events.Event, len(Events))
	for key, val := range Events {
		ret[key] = val
	}

	return ret, rawRet, nil
}

func LoadRuleFile(rulefile string) (map[string]Rule, error) {
	ruleset := make(map[string]Rule)
	rulefilePath := MakeAssetFullPath(rulefile)
	rawRules, err := ParseYAMLRulesFile(rulefilePath)
	if err != nil {
		return map[string]Rule{}, err
	}
	for name, rawRule := range rawRules {
		ruleset[name] = rawRule.Parse()
	}

	return ruleset, nil
}

func MakeAssetFullPath(path string) string {
	return fmt.Sprintf("%s/%s", assetsBasePath, path)
}
