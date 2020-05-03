package rules

import (
	"log"
	"strconv"

	"github.com/bonjourmalware/pinknoise/internal/iprules"
)

// The yml rule file contains multiple named rules
type RawRules map[string]RawRule

// Each named rule contains multiple conditions for multiple fields
type RawRule struct {
	Ports      *[]string           `yaml:"ports"`
	Id         string              `yaml:"id"`
	Logto      *string             `yaml:"logto"`
	Tags       []string            `yaml:"tags"`
	Layer      string              `yaml:"layer"`
	TTL        *uint8              `yaml:"ttl"`
	IPOption   RawConditions       `yaml:"ipoption"`
	Window     *uint16             `yaml:"window"`
	TOS        *uint8              `yaml:"tos"`
	Fragbits   RawFragbitsList     `yaml:"fragbits"`
	Dsize      *int                `yaml:"dsize"`
	Flags      RawTCPFlagsList     `yaml:"flags"`
	Seq        *uint32             `yaml:"seq"`
	Ack        *uint32             `yaml:"ack"`
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
	IPs        []string            `yaml:"ip"`
	Offset     int                 `yaml:"offset"`
	Depth      int                 `yaml:"depth"`
	MatchType  string              `yaml:"match"`
}

func (rawRule RawRule) Parse() Rule {
	var iport uint64
	var ports []uint
	var err error
	var ipsList = iprules.IPRules{
		WhitelistedIPs: iprules.IPRanges{},
		BlacklistedIPs: iprules.IPRanges{},
	}

	ipsList.ParseRules(rawRule.IPs)

	if rawRule.Ports != nil {
		for _, port := range *rawRule.Ports {
			iport, err = strconv.ParseUint(port, 10, 32)
			if err != nil {
				log.Printf("Invalid port \"%s\" for rule %s\n", port, rawRule.Id)
				continue
			}
			ports = append(ports, uint(iport))
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

	return rule
}
