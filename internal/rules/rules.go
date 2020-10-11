package rules

import (
	"github.com/bonjourmalware/pinknoise/internal/iprules"
)

type Rules []Rule

type Rule struct {
	// Global
	Name  string
	Ports []uint
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
	UDPLength   *uint16
	Checksum *uint16

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

func (rawRules RawRules) Parse() Rules {
	rules := Rules{}
	for rname, rule := range rawRules {
		parsedRule := rule.Parse()
		parsedRule.Name = rname
		rules = append(rules, parsedRule)
	}

	return rules
}
