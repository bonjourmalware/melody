package engine

import (
	"github.com/bonjourmalware/pinknoise/internal/events"
	"github.com/bonjourmalware/pinknoise/internal/logger"
	"github.com/bonjourmalware/pinknoise/internal/rules"
)

var (
	EventChan = make(chan events.Event)
)

func Start(quitErrChan chan error, shutdownChan chan bool, engineStoppedChan chan bool) {
	go startEventQualifier(quitErrChan, shutdownChan, engineStoppedChan)
}

func startEventQualifier(quitErrChan chan error, shutdownChan chan bool, engineStoppedChan chan bool) {
	defer func() {
		close(engineStoppedChan)
	}()

	for {
		select {
		case <-shutdownChan:
			return

		case <-quitErrChan:
			return

		case ev := <-EventChan:
			var matches []rules.Rule

			for _, ruleset := range rules.GlobalRules[ev.GetKind()] {
				for _, rule := range ruleset {
					if rule.Match(ev) {
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

			logger.LogChan <- ev

		default:
		}
	}
}
