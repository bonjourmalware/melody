package rules

import (
	"bufio"
	"bytes"
	"net/http"
	"testing"

	"github.com/bonjourmalware/pinknoise/internal/config"

	"github.com/google/gopacket/layers"
	"github.com/bonjourmalware/pinknoise/internal/events"
)

func TestMatchICMPv4Event(t *testing.T) {
	ruleFilename := "icmp_rules.yml"
	pcapFilename := "icmp_values.pcap"
	rawPackets := false
	var rule Rule

	ruleset, err := LoadRuleFile(ruleFilename)
	if err != nil {
		t.Error(err)
		return
	}

	filteredEvents, err := ReadPacketsFromPcap(pcapFilename, layers.IPProtocolICMPv4, rawPackets)
	if err != nil {
		t.Error(err)
		return
	}

	if filteredEvents[0] == nil {
		t.Error("No ICMP packets has been read from pcap")
		return
	}

	tests := []struct {
		Ok     []string
		Nok    []string
		Packet events.ICMPv4Event
	}{
		{
			Ok: []string{
				"ok_ttl",
				"ok_tos",
			},
			Nok: []string{
				"nok_ttl",
				"nok_tos",
			},
			Packet: *(filteredEvents[0].(*events.ICMPv4Event)),
		},
	}

	for _, suite := range tests {
		for _, rulename := range suite.Ok {
			rule = ruleset[rulename]
			if ok := rule.MatchICMPv4Event(suite.Packet); !ok {
				t.Error(rulename, "FAILED")
				t.Fail()
			}
		}
		for _, rulename := range suite.Nok {
			rule = ruleset[rulename]
			if ok := rule.MatchICMPv4Event(suite.Packet); ok {
				t.Error(rulename, "FAILED")
				t.Fail()
			}
		}
	}
}

func TestMatchTCPEvent(t *testing.T) {
	ruleFilename := "tcp_rules.yml"
	pcapFilename := "tcp_values.pcap"
	rawPackets := false
	var rule Rule

	ruleset, err := LoadRuleFile(ruleFilename)
	if err != nil {
		t.Error(err)
		return
	}

	filteredEvents, err := ReadPacketsFromPcap(pcapFilename, layers.IPProtocolTCP, rawPackets)
	if err != nil {
		t.Error(err)
		return
	}

	if filteredEvents[0] == nil {
		t.Error("No TCP packets has been read from pcap")
		return
	}

	tests := []struct {
		Ok     []string
		Nok    []string
		Packet events.TCPEvent
	}{
		{
			Ok: []string{
				"ok_ttl",
				"ok_tos",
				"ok_ack",
				"ok_seq",
				"ok_window",
			},
			Nok: []string{
				"nok_ttl",
				"nok_tos",
				"nok_ack",
				"nok_seq",
				"nok_window",
			},
			Packet: *(filteredEvents[1].(*events.TCPEvent)),
		},
		{
			Ok: []string{
				"ok_dsize",
				"ok_payload",
			},
			Nok: []string{
				"nok_dsize",
				"nok_payload",
			},
			Packet: *(filteredEvents[2].(*events.TCPEvent)),
		},
		{
			Ok: []string{
				"ok_flags",
				"ok_fragbits",
			},
			Nok: []string{
				"nok_flags",
				"nok_fragbits",
			},
			Packet: *(filteredEvents[4].(*events.TCPEvent)),
		},
	}

	for _, suite := range tests {
		for _, rulename := range suite.Ok {
			rule = ruleset[rulename]
			if ok := rule.MatchTCPEvent(suite.Packet); !ok {
				t.Error(rulename, "FAILED")
				t.Fail()
			}
		}
		for _, rulename := range suite.Nok {
			rule = ruleset[rulename]
			if ok := rule.MatchTCPEvent(suite.Packet); ok {
				t.Error(rulename, "FAILED")
				t.Fail()
			}
		}
	}
}

func TestMatchHTTPEvent(t *testing.T) {
	ruleFilename := "http_rules.yml"
	pcapFilename := "http_values.pcap"
	var httpEvents []*events.HTTPEvent
	var rule Rule

	// Allow POST data to be parsed without loading the config.yml file
	config.Cfg.MaxPOSTDataSize = 8191

	ruleset, err := LoadRuleFile(ruleFilename)
	if err != nil {
		t.Error(err)
		return
	}

	packets, err := ReadRawTCPPacketsFromPcap(pcapFilename)
	if err != nil {
		t.Error(err)
		return
	}

	// Will fail on packets needing reassembly
	// Good enough for testing
	for _, packet := range packets {
		if len(packet.TransportLayer().LayerPayload()) > 0 {
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(packet.TransportLayer().LayerPayload())))
			if err != nil {
				t.Error(err)
				return
			}

			ev := events.NewHTTPEvent(req, packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow())
			if len(ev.Errors) > 0 {
				for _, err := range ev.Errors {
					t.Error(err)
				}
				return
			}
			httpEvents = append(httpEvents, ev)
		}
	}

	if httpEvents == nil {
		t.Error("No HTTP packets has been read from pcap")
		return
	}

	tests := []struct {
		Ok     []string
		Nok    []string
		Packet events.HTTPEvent
	}{
		{
			Ok: []string{
				"ok_uri",
				"ok_body",
				"ok_headers",
				"ok_proto",
				"ok_method",
			},
			Nok: []string{
				"nok_uri",
				"nok_body",
				"nok_headers",
				"nok_proto",
				"nok_method",
			},
			Packet: *httpEvents[0],
		},
	}

	for _, suite := range tests {
		for _, rulename := range suite.Ok {
			rule = ruleset[rulename]
			if ok := rule.MatchHTTPEvent(suite.Packet); !ok {
				t.Error(rulename, "FAILED")
				t.Fail()
			}
		}
		for _, rulename := range suite.Nok {
			rule = ruleset[rulename]
			if ok := rule.MatchHTTPEvent(suite.Packet); ok {
				t.Error(rulename, "FAILED")
				t.Fail()
			}
		}
	}
}
