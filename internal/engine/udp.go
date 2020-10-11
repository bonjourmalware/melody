package engine

import (
	"github.com/bonjourmalware/pinknoise/internal/events"
	"github.com/bonjourmalware/pinknoise/internal/rules"
)

func qualifyUDPEvent(ev *events.UDPEvent) {
	var matches []rules.Rule

	for _, rules := range rules.GlobalRules {
		for _, rule := range rules {
			if rule.Layer != ev.Kind {
				continue
			}
			if rule.MatchUDPEvent(*ev) {
				matches = append(matches, rule)
			}
		}
	}

	if len(matches) > 0 {
		for _, match := range matches {
			ev.AddTags(match.Tags)
			ev.AddMeta(match.Metadata)
			ev.AddRefs(match.References)
			ev.AddStatements(match.Statements)
		}
	}
}
