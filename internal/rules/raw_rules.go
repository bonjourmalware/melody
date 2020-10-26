package rules

import (
	"log"
	"strconv"

	"github.com/google/gopacket/layers"

	"github.com/bonjourmalware/pinknoise/internal/iprules"
)

// The yml rule file contains multiple named rules
type RawRules map[string]RawRule

// Each named rule contains multiple conditions for multiple fields
type RawRule struct {
	Ports    *[]string       `yaml:"ports"`
	Id       string          `yaml:"id"`
	Logto    *string         `yaml:"logto"`
	Tags     []string        `yaml:"tags"`
	Layer    string          `yaml:"layer"`
	TTL      *uint8          `yaml:"ttl"`
	IPOption RawConditions   `yaml:"ipoption"`
	Window   *uint16         `yaml:"window"`
	TOS      *uint8          `yaml:"tos"`
	Fragbits RawFragbitsList `yaml:"fragbits"`
	Dsize    *int            `yaml:"dsize"`
	Flags    RawTCPFlagsList `yaml:"flags"`
	Seq      *uint32         `yaml:"seq"`
	Ack      *uint32         `yaml:"ack"`

	TypeCode6 *layers.ICMPv6TypeCode `yaml:"icmpv6_type_code"`
	ICMPType6 *uint8                 `yaml:"icmpv6_type"`
	ICMPCode6 *uint8                 `yaml:"icmpv6_code"`

	TypeCode4 *layers.ICMPv4TypeCode `yaml:"icmpv4_type_code"`
	ICMPType4 *uint8                 `yaml:"icmpv4_type"`
	ICMPCode4 *uint8                 `yaml:"icmpv4_code"`
	ICMPSeq   *uint16                `yaml:"icmpv4_seq"`

	UDPLength  *uint16             `yaml:"udplength"`
	Checksum   *uint16             `yaml:"checksum"`
	Payload    RawConditions       `yaml:"payload"`
	IPProtocol RawConditions       `yaml:"ip_protocol"`
	URI        RawConditions       `yaml:"uri"`
	Body       RawConditions       `yaml:"body"`
	Headers    RawConditions       `yaml:"headers"`
	Verb       RawConditions       `yaml:"method"`
	Proto      RawConditions       `yaml:"proto"`
	TLS        *bool               `yaml:"tls"`
	Metadata   map[string]string   `yaml:"metadata"`
	Statements []string            `yaml:"statements"`
	References map[string][]string `yaml:"references"`
	IPs        []string            `yaml:"src_ips"`
	Offset     int                 `yaml:"offset"`
	Depth      int                 `yaml:"depth"`
	MatchType  string              `yaml:"match"`
}

func (rawRule RawRule) Parse() Rule {
	var iport uint64
	var ports []uint16
	var err error
	var ipsList = iprules.IPRules{
		WhitelistedIPs: iprules.IPRanges{},
		BlacklistedIPs: iprules.IPRanges{},
	}

	ipsList.ParseRules(rawRule.IPs)

	if rawRule.Ports != nil {
		for _, port := range *rawRule.Ports {
			iport, err = strconv.ParseUint(port, 10, 16)
			if err != nil {
				log.Printf("Invalid port \"%s\" for rule %s\n", port, rawRule.Id)
				continue
			}
			ports = append(ports, uint16(iport))
		}
	}

	rule := Rule{
		Ports:      ports,
		Payload:    rawRule.Payload.ParseList(rawRule.Id),
		IPOption:   rawRule.IPOption.ParseList(rawRule.Id),
		Tags:       rawRule.Tags,
		TTL:        rawRule.TTL,
		TOS:        rawRule.TOS,
		Dsize:      rawRule.Dsize,
		Seq:        rawRule.Seq,
		Ack:        rawRule.Ack,
		IPProtocol: rawRule.IPProtocol.ParseList(rawRule.Id),
		URI:        rawRule.URI.ParseList(rawRule.Id),
		Body:       rawRule.Body.ParseList(rawRule.Id),
		Verb:       rawRule.Verb.ParseList(rawRule.Id),
		Headers:    rawRule.Headers.ParseList(rawRule.Id),
		Proto:      rawRule.Proto.ParseList(rawRule.Id),
		Fragbits:   rawRule.Fragbits.ParseList(),
		Flags:      rawRule.Flags.ParseList(),
		Window:     rawRule.Window,
		TLS:        rawRule.TLS,
		ICMPSeq:    rawRule.ICMPSeq,
		TypeCode4:  rawRule.TypeCode4,
		ICMPCode4:  rawRule.ICMPCode4,
		ICMPType4:  rawRule.ICMPType4,
		TypeCode6:  rawRule.TypeCode6,
		ICMPCode6:  rawRule.ICMPCode6,
		ICMPType6:  rawRule.ICMPType6,
		UDPLength:  rawRule.UDPLength,
		Checksum:   rawRule.Checksum,
		Id:         rawRule.Id,
		Layer:      rawRule.Layer,
		IPs:        ipsList,
		Metadata:   rawRule.Metadata,
		Statements: rawRule.Statements,
		References: rawRule.References,
		Options: RuleOptions{
			Depth:    rawRule.Depth,
			Offset:   rawRule.Offset,
			MatchAll: rawRule.MatchType == "all",
			MatchAny: rawRule.MatchType == "any",
		},
	}

	// Default to MatchAll
	if rule.Options.MatchAll == false && rule.Options.MatchAny == false {
		rule.Options.MatchAll = true
	}

	return rule
}
