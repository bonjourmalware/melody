package rules

import (
	"github.com/bonjourmalware/pinknoise/internal/iprules"
	"github.com/google/gopacket/layers"
)

type Rules []Rule

type Rule struct {
	// Global
	Name  string
	Ports []uint16
	Logto string
	Id    string
	Tags  []string

	// TCP/IP
	TTL *uint8
	TOS *uint8
	//ID       *uint16
	IPOption *ConditionsList
	Fragbits []*uint8
	Dsize    *int
	Flags    []*uint8
	Seq      *uint32
	Ack      *uint32
	Payload  *ConditionsList
	Offset   int
	Depth    int
	Window   *uint16
	Layer    string

	IPProtocol *ConditionsList

	// UDP
	UDPLength *uint16
	Checksum  *uint16

	// ICMPv6
	TypeCode6 *layers.ICMPv6TypeCode
	ICMPCode6 *uint8
	ICMPType6 *uint8

	// ICMPv4
	TypeCode4 *layers.ICMPv4TypeCode
	ICMPCode4 *uint8
	ICMPType4 *uint8
	//Seq      *uint32
	ICMPSeq *uint16

	//	HTTP
	URI     *ConditionsList
	Body    *ConditionsList
	Headers *ConditionsList
	IPs     iprules.IPRules
	Verb    *ConditionsList
	Proto   *ConditionsList
	TLS     *bool

	Metadata   map[string]string
	Statements []string
	References map[string][]string

	Options RuleOptions
}

type RuleOptions struct {
	Depth    int
	Offset   int
	MatchAll bool
	MatchAny bool
}

func (rules Rules) Filter(fn func(rule Rule) bool) Rules {
	res := Rules{}

	for _, rule := range rules {
		if fn(rule) {
			res = append(res, rule)
		}
	}

	return res
}

func (rawRules RawRules) Parse() Rules {
	rules := Rules{}
	for rname, rule := range rawRules {
		parsedRule := rule.Parse()
		parsedRule.Name = rname
		rules = append(rules, parsedRule)
	}

	return rules
}
