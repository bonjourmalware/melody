package rules

import (
	"github.com/bonjourmalware/pinknoise/internal/iprules"
)

type Rules []Rule

type Rule struct {
	// Global
	Name  string
	Ports []uint16
	Logto string
	Id    string
	Tags  []string

	Layer    string

	IPProtocol *ConditionsList

	HTTP ParsedHTTPRule
	TCP  ParsedTCPRule
	UDP  ParsedUDPRule
	ICMPv4  ParsedICMPv4Rule
	ICMPv6  ParsedICMPv6Rule

	IPs        iprules.IPRules
	Metadata   map[string]string
	Statements []string
	References map[string][]string

	MatchAll bool
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
