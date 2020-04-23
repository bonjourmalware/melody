package rules

import (
	"fmt"
	"strconv"

	"gitlab.com/Alvoras/pinknoise/internal/iprules"
)

type RawRule struct {
	Ports    *[]string              `yaml:"ports"`
	Logto    *string                `yaml:"logto"`
	TTL      *uint8                 `yaml:"ttl"`
	TOS      *uint8                 `yaml:"tos"`
	ID       *uint16                `yaml:"id"`
	IPOption RawReversableValueList `yaml:"ipoption"`
	Fragbits RawReversableValueList `yaml:"fragbits"`
	Dsize    *int                   `yaml:"dsize"`
	Flags    RawReversableValueList `yaml:"flags"`
	Seq      *uint32                `yaml:"seq"`
	Ack      *uint32                `yaml:"ack"`
	Payload RawReversableValueList `yaml:"payload"`
	Offset  int                    `yaml:"offset"`
	Depth   int                    `yaml:"depth"`
	Window  *uint16                `yaml:"window"`
	Nocase  *bool                  `yaml:"nocase"`
	Sid     *uint64                `yaml:"sid"`
	Tags    []string               `yaml:"tags"`
	Layer   string                 `yaml:"layer"`
	IPProtocol RawReversableValueList `yaml:"ip_protocol"`
	URI        RawReversableValueList `yaml:"uri"`
	Body       RawReversableValueList `yaml:"body"`
	Headers    RawReversableValueList `yaml:"headers"`
	IPs        []string               `yaml:"ip"`
	Verb       RawReversableValueList `yaml:"verb"`
	Proto      RawReversableValueList `yaml:"proto"`
	TLS        *bool                  `yaml:"tls"`
	Metadata   map[string]string      `yaml:"metadata"`
	Statements []string               `yaml:"statements"`
	References map[string][]string    `yaml:"references"`
}

//TODO : Add ip_proto parameter
type Rule struct {
	// Global
	Name  string
	Ports []uint
	Logto  string
	Nocase *bool
	Sid    *uint64
	Tags   []string

	// TCP/IP
	TTL      *uint8
	TOS      *uint8
	ID       *uint16
	IPOption ReversableValueList
	Fragbits *uint8
	Dsize   *int
	Flags   *uint8
	Seq     *uint32
	Ack     *uint32
	Payload ReversableValueList
	Offset  int
	Depth   int
	Window  *uint16
	Layer string

	IPProtocol ReversableValueList

	//	HTTP
	URI     ReversableValueList
	Body    ReversableValueList
	Headers ReversableValueList
	IPs     iprules.IPRules
	Verb    ReversableValueList
	Proto   ReversableValueList
	TLS     *bool

	Metadata   map[string]string
	Statements []string
	References map[string][]string
}

type Options struct {
	Nocase bool `yaml:"nocase"`
	And    bool `yaml:"and"`
	Exact  bool `yaml:"exact"`
}

type GlobalRawRules []RawRules
type RawRules map[string]RawRule

type Rules []Rule

var (
	GlobalRules []Rules
)

//TODO: Change shitty struct alias in methods (eg. "rrs")
func (rrs RawRules) Parse() Rules {
	rules := Rules{}
	for rname, rule := range rrs {
		parsedRule := rule.Parse()
		parsedRule.Name = rname
		rules = append(rules, parsedRule)
	}

	return rules
}

func (rr RawRule) Parse() Rule {
	var iport uint64
	var ports []uint
	var err error
	var flags uint8
	var fragbits uint8
	var flagsOptSet = false
	var fragbitsOptSet = false
	var ipsList = iprules.IPRules{
		WhitelistedIPs: iprules.IPRanges{},
		BlacklistedIPs: iprules.IPRanges{},
	}

	ipsList.ParseRules(rr.IPs)

	if rr.Ports != nil {
		for _, port := range *rr.Ports {
			iport, err = strconv.ParseUint(port, 10, 32)
			if err != nil {
				fmt.Println("Invalid port \"%s\" for rule %d", port, rr.Sid)
				continue
			}
			ports = append(ports, uint(iport))
		}
	}

	if len(rr.Flags.Values) > 0 {
		flagsOptSet = true
		//TODO Add support for "Not" option
		for _, val := range rr.Flags.Values {
			switch val {
			case "F":
				flags |= 0x01
			case "S":
				flags |= 0x02
			case "R":
				flags |= 0x04
			case "P":
				flags |= 0x08
			case "A":
				flags |= 0x10
			case "U":
				flags |= 0x20
			case "E":
				flags |= 0x40
			case "C":
				flags |= 0x80
			case "0":
				flags = 0
			default:
				fmt.Println("Unknown flag value :", val)
			}
		}
	}

	//TODO Add support for "Not" option
	if len(rr.Fragbits.Values) > 0 {
		fragbitsOptSet = true
		for _, val := range rr.Fragbits.Values {
			switch val {
			case "M":
				fallthrough
			case "MF":
				fragbits |= 0x01
			case "D":
				fallthrough
			case "DF":
				fragbits |= 0x02
			case "R":
				fallthrough
			case "RF":
				fragbits |= 0x04
			default:
				fmt.Println("Unknown flag value :", val)
			}
		}
	}

	r := Rule{
		Ports:    ports,
		Payload:  rr.Payload.Parse(),
		IPOption: rr.IPOption.Parse(),
		Tags:     rr.Tags,
		TTL:        rr.TTL,
		TOS:        rr.TOS,
		ID:         rr.ID,
		Dsize:      rr.Dsize,
		Seq:        rr.Seq,
		Ack:        rr.Ack,
		IPProtocol: rr.IPProtocol.Parse(),
		URI:        rr.URI.Parse(),
		Body:       rr.Body.Parse(),
		Verb:       rr.Verb.Parse(),
		Headers:    rr.Headers.Parse(),
		Proto:      rr.Proto.Parse(),
		Window:   rr.Window,
		Nocase:   rr.Nocase,
		Sid:      rr.Sid,
		Layer:    rr.Layer,
		IPs:      ipsList,
		Metadata: rr.Metadata,
		Statements: rr.Statements,
		References: rr.References,
	}

	if !flagsOptSet {
		r.Flags = nil
	} else {
		r.Flags = &flags
	}

	if !fragbitsOptSet {
		r.Fragbits = nil
	} else {
		r.Fragbits = &fragbits
	}

	return r
}