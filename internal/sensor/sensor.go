package sensor

import (
	"fmt"
	"os"
	"time"

	"github.com/bonjourmalware/melody/internal/logging"

	"github.com/bonjourmalware/melody/internal/engine"
	"github.com/bonjourmalware/melody/internal/events"
	"github.com/google/gopacket/layers"

	"github.com/bonjourmalware/melody/internal/sessions"

	"github.com/bonjourmalware/melody/internal/config"
	"github.com/bonjourmalware/melody/internal/assembler"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

func Start(quitErrChan chan error, shutdownChan chan bool, sensorStoppedChan chan bool) {
	go ReceivePackets(quitErrChan, shutdownChan, sensorStoppedChan)
}

func ReceivePackets(quitErrChan chan error, shutdownChan chan bool, sensorStoppedChan chan bool) {
	// Set up HTTP assembly
	streamFactory := &assembler.HttpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	var handle *pcap.Handle
	var err error

	if config.Cfg.PcapFile != nil {
		handle, err = pcap.OpenOfflineFile(config.Cfg.PcapFile)
		if err != nil {
			quitErrChan <- err
			close(sensorStoppedChan)
			time.Sleep(2 * time.Second)
			logging.Errors.Println(err)
			logging.Errors.Println("Failed to shutdown gracefully, exiting now.")
			os.Exit(1)
		}
	} else {
		// Open up a pcap handle for packet reads/writes.
		handle, err = pcap.OpenLive(config.Cfg.Interface, 65536, true, pcap.BlockForever)
		if err != nil {
			quitErrChan <- err
			close(sensorStoppedChan)
			time.Sleep(2 * time.Second)
			logging.Errors.Println(err)
			logging.Errors.Println("Failed to shutdown gracefully, exiting now.")
			os.Exit(1)
		}
	}

	defer handle.Close()
	if config.Cfg.BPFFilter != "" {
		if err := handle.SetBPFFilter(config.Cfg.BPFFilter); err != nil {
			quitErrChan <- err
			time.Sleep(2 * time.Second)
			logging.Errors.Println(err)
			logging.Errors.Println("Failed to shutdown gracefully, exiting now.")
			os.Exit(1)
		}
	}

	assemblerFlushTicker := time.NewTicker(time.Minute)
	sessionsFlushTicker := time.NewTicker(time.Second * 30)
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()
	logging.Std.Println("Now listening for packets")

	defer func() {
		assembler.FlushAll()
		sessions.Map.FlushAll()
		close(sensorStoppedChan)
	}()

loop:
	for {
		var packet gopacket.Packet
		select {
		case packet = <-in:
			if packet == nil {
				break loop
			}
			handlePacket(packet, assembler)
		case <-assemblerFlushTicker.C:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		case <-sessionsFlushTicker.C:
			// Every 30 seconds, flush inactive flows
			sessions.Map.FlushOlderThan(time.Now().Add(time.Second * -30))
		case <-shutdownChan:
			return
		}
	}

	close(shutdownChan)
}

func handlePacket(packet gopacket.Packet, assembler *tcpassembly.Assembler) {
	var event events.Event
	var err error

	if packet.NetworkLayer() != nil {
		if _, ok := packet.NetworkLayer().(*layers.IPv4); ok {
			switch packet.NetworkLayer().(*layers.IPv4).Protocol {
			case layers.IPProtocolICMPv4:
				if _, ok := config.Cfg.DiscardProto4[config.ICMPv4Kind]; ok {
					return
				}

				event, err = events.NewICMPv4Event(packet)
				if err != nil {
					logging.Errors.Println(err)
					return
				}

			case layers.IPProtocolUDP:
				if _, ok := config.Cfg.DiscardProto4[config.UDPKind]; ok {
					return
				}

				event, err = events.NewUDPEvent(packet, 4)
				if err != nil {
					logging.Errors.Println(err)
					return
				}

			case layers.IPProtocolTCP:
				tcpPacket := packet.TransportLayer().(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcpPacket, packet.Metadata().Timestamp)

				if _, ok := config.Cfg.DiscardProto4[config.TCPKind]; ok {
					return
				}

				event, err = events.NewTCPEvent(packet, 4)
				if err != nil {
					logging.Errors.Println(err)
					return
				}

			default:
				return
			}

			if *config.Cli.Dump {
				fmt.Println(packet.String())
			} else {
				engine.EventChan <- event
			}
		} else if _, ok := packet.NetworkLayer().(*layers.IPv6); ok {
			switch packet.NetworkLayer().(*layers.IPv6).NextHeader {
			case layers.IPProtocolICMPv6:
				if _, ok := config.Cfg.DiscardProto6[config.ICMPv6Kind]; ok {
					return
				}

				event, err = events.NewICMPv6Event(packet)
				if err != nil {
					logging.Errors.Println(err)
					return
				}

			default:
				switch packet.NetworkLayer().(*layers.IPv6).NextLayerType() {
				case layers.IPProtocolTCP.LayerType():
					tcpPacket := packet.TransportLayer().(*layers.TCP)
					assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcpPacket, packet.Metadata().Timestamp)

					if _, ok := config.Cfg.DiscardProto6[config.TCPKind]; ok {
						return
					}

					event, err = events.NewTCPEvent(packet, 6)
					if err != nil {
						logging.Errors.Println(err)
						return
					}

				case layers.IPProtocolUDP.LayerType():
					if _, ok := config.Cfg.DiscardProto6[config.UDPKind]; ok {
						return
					}

					event, err = events.NewUDPEvent(packet, 6)
					if err != nil {
						logging.Errors.Println(err)
						return
					}

				default:
					return
				}
			}

			if *config.Cli.Dump {
				fmt.Println(packet.String())
			} else {
				engine.EventChan <- event
			}
		}
	}
}
