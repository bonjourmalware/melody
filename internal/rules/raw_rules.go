package rules

import (
	"os"
	"strings"

	"github.com/bonjourmalware/pinknoise/internal/logging"

	"github.com/bonjourmalware/pinknoise/internal/filters"
	"github.com/go-yaml/yaml"
)

// The yml rule file contains multiple named rules
type RawRules map[string]RawRule

type HTTPRule struct {
	URI     RawConditions `yaml:"http.uri"`
	Body    RawConditions `yaml:"http.body"`
	Headers RawConditions `yaml:"http.headers"`
	Verb    RawConditions `yaml:"http.method"`
	Proto   RawConditions `yaml:"http.proto"`
	TLS     *bool         `yaml:"http.tls"`
	Any     bool          `yaml:"any"`
}

type ParsedHTTPRule struct {
	URI     *ConditionsList
	Body    *ConditionsList
	Headers *ConditionsList
	Verb    *ConditionsList
	Proto   *ConditionsList
	TLS     *bool
}

type TCPRule struct {
	IPOption RawConditions   `yaml:"tcp.ipoption"`
	Fragbits RawFragbitsList `yaml:"tcp.fragbits"`
	Dsize    *uint           `yaml:"tcp.dsize"`
	Flags    RawTCPFlagsList `yaml:"tcp.flags"`
	Seq      *uint32         `yaml:"tcp.seq"`
	Ack      *uint32         `yaml:"tcp.ack"`
	Payload  RawConditions   `yaml:"tcp.payload"`
	Window   *uint16         `yaml:"tcp.window"`
	Any      bool            `yaml:"any"`
}

type ParsedTCPRule struct {
	IPOption *ConditionsList
	Fragbits []*uint8
	Dsize    *uint
	Flags    []*uint8
	Seq      *uint32
	Ack      *uint32
	Payload  *ConditionsList
	Window   *uint16
}

type ICMPv4Rule struct {
	TypeCode *uint16 `yaml:"icmpv4.typecode"`
	Type     *uint8  `yaml:"icmpv4.type"`
	Code     *uint8  `yaml:"icmpv4.code"`
	Checksum *uint16 `yaml:"icmpv4.checksum"`
	Seq      *uint16 `yaml:"icmpv4.seq"`
	Any      bool    `yaml:"any"`
}

type ICMPv6Rule struct {
	TypeCode *uint16 `yaml:"icmpv6.typecode"`
	Type     *uint8  `yaml:"icmpv6.type"`
	Code     *uint8  `yaml:"icmpv6.code"`
	Checksum *uint16 `yaml:"icmpv6.checksum"`
	Any      bool    `yaml:"any"`
}

type ParsedICMPv4Rule struct {
	TypeCode *uint16
	Type     *uint8
	Code     *uint8
	Checksum *uint16
	Seq      *uint16
}

type ParsedICMPv6Rule struct {
	TypeCode *uint16
	Type     *uint8
	Code     *uint8
	Checksum *uint16
}

type UDPRule struct {
	Length   *uint16       `yaml:"udp.length"`
	Dsize    *uint         `yaml:"udp.dsize"`
	Checksum *uint16       `yaml:"udp.checksum"`
	Payload  RawConditions `yaml:"udp.payload"`
	Any      bool          `yaml:"any"`
}

type ParsedUDPRule struct {
	Length   *uint16
	Dsize    *uint
	Checksum *uint16
	Payload  *ConditionsList
}

type Filters struct {
	Ports []string `yaml:"ports"`
	IPs   []string `yaml:"ips"`
}

type RawRule struct {
	Whitelist Filters `yaml:"whitelist"`
	Blacklist Filters `yaml:"blacklist"`

	Match interface{} `yaml:"match"`

	Id         string        `yaml:"id"`
	Logto      *string       `yaml:"logto"`
	Tags       []string      `yaml:"tags"`
	Layer      string        `yaml:"layer"`
	IPProtocol RawConditions `yaml:"ip_protocol"`

	Metadata   map[string]string `yaml:"metadata"`
	References []string          `yaml:"references"`
	Offset     int               `yaml:"offset"`
	Depth      int               `yaml:"depth"`
	Any        bool              `yaml:"match.any"`
}

func (rawRule RawRule) Parse() Rule {
	var err error
	var portsList = filters.PortRules{
		WhitelistedPorts: filters.PortRanges{},
		BlacklistedPorts: filters.PortRanges{},
	}

	var ipsList = filters.IPRules{
		WhitelistedIPs: filters.IPRanges{},
		BlacklistedIPs: filters.IPRanges{},
	}

	ipsList.ParseRules(rawRule.Whitelist.IPs, rawRule.Blacklist.IPs)
	portsList.ParseRules(rawRule.Whitelist.Ports, rawRule.Blacklist.Ports)

	rule := Rule{
		Tags:       rawRule.Tags,
		IPProtocol: rawRule.IPProtocol.ParseList(rawRule.Id),
		Id:         rawRule.Id,
		Layer:      rawRule.Layer,
		Ports:      portsList,
		IPs:        ipsList,
		Metadata:   rawRule.Metadata,
		References: rawRule.References,
	}

	if rawRule.Match == nil {
		return rule
	}

	rawMatch, err := yaml.Marshal(rawRule.Match)
	if err != nil {
		logging.Errors.Println(err)
		// Fatal error
		os.Exit(1)
	}

	for key := range rawRule.Match.(map[interface{}]interface{}) {
		// "any" is the only valid non-layer specific property in the "match" block
		if key.(string) != "any" && !strings.HasPrefix(key.(string), rawRule.Layer+".") {
			logging.Warnings.Printf("Property '%s' is not supported with layer '%s'", key.(string), rawRule.Layer)
			return Rule{}
		}
	}

	switch rawRule.Layer {
	case "http":
		var buf HTTPRule

		err = yaml.Unmarshal(rawMatch, &buf)
		if err != nil {
			logging.Warnings.Printf("failed to parse rule '%s' (layer: '%s') : %s", rawRule.Id, rawRule.Layer, err)
			return Rule{}
		}

		rule.HTTP = ParsedHTTPRule{
			URI:     buf.URI.ParseList(rawRule.Id),
			Body:    buf.Body.ParseList(rawRule.Id),
			Verb:    buf.Verb.ParseList(rawRule.Id),
			Headers: buf.Headers.ParseList(rawRule.Id),
			Proto:   buf.Proto.ParseList(rawRule.Id),
			TLS:     buf.TLS,
		}

		rule.MatchAll = !buf.Any

	case "tcp":
		var buf TCPRule

		err = yaml.Unmarshal(rawMatch, &buf)
		if err != nil {
			logging.Warnings.Printf("failed to parse rule '%s' (layer: '%s') : %s", rawRule.Id, rawRule.Layer, err)
			return Rule{}
		}

		rule.TCP = ParsedTCPRule{
			IPOption: buf.IPOption.ParseList(rawRule.Id),
			Fragbits: buf.Fragbits.ParseList(),
			Flags:    buf.Flags.ParseList(),
			Window:   buf.Window,
			Dsize:    buf.Dsize,
			Seq:      buf.Seq,
			Ack:      buf.Ack,
			Payload:  buf.Payload.ParseList(rawRule.Id),
		}

		rule.MatchAll = !buf.Any

	case "udp":
		var buf UDPRule

		err = yaml.Unmarshal(rawMatch, &buf)
		if err != nil {
			logging.Warnings.Printf("failed to parse rule '%s' (layer: '%s') : %s", rawRule.Id, rawRule.Layer, err)
			return Rule{}
		}

		rule.UDP = ParsedUDPRule{
			Dsize:    buf.Dsize,
			Length:   buf.Length,
			Checksum: buf.Checksum,
			Payload:  buf.Payload.ParseList(rawRule.Id),
		}

		rule.MatchAll = !buf.Any

	case "icmpv4":
		var buf ICMPv4Rule

		err = yaml.Unmarshal(rawMatch, &buf)
		if err != nil {
			logging.Warnings.Printf("failed to parse rule '%s' (layer: '%s') : %s", rawRule.Id, rawRule.Layer, err)
			return Rule{}
		}

		rule.ICMPv4 = ParsedICMPv4Rule{
			TypeCode: buf.TypeCode,
			Type:     buf.Type,
			Code:     buf.Code,
			Checksum: buf.Checksum,
			Seq:      buf.Seq,
		}

		rule.MatchAll = !buf.Any

	case "icmpv6":
		var buf ICMPv6Rule

		err = yaml.Unmarshal(rawMatch, &buf)
		if err != nil {
			logging.Warnings.Printf("failed to parse rule '%s' (layer: '%s') : %s", rawRule.Id, rawRule.Layer, err)
			return Rule{}
		}

		rule.ICMPv6 = ParsedICMPv6Rule{
			TypeCode: buf.TypeCode,
			Type:     buf.Type,
			Code:     buf.Code,
			Checksum: buf.Checksum,
		}

		rule.MatchAll = !buf.Any
	}

	return rule
}
