package engine

import (
	"github.com/bonjourmalware/pinknoise/internal/config"
	"github.com/bonjourmalware/pinknoise/internal/events"
	"github.com/bonjourmalware/pinknoise/internal/logging"
	"github.com/bonjourmalware/pinknoise/internal/router"
	"github.com/bonjourmalware/pinknoise/internal/rules"
)

var (
	EventChan = make(chan events.Event)
)

func Start(quitErrChan chan error, shutdownChan chan bool, engineStoppedChan chan bool) {
	go startEventQualifier(quitErrChan, shutdownChan, engineStoppedChan)

	if config.Cfg.ServerHTTPEnable {
		logging.Std.Println("Starting HTTP server...")
		go router.StartHTTP(quitErrChan)
	}

	if config.Cfg.ServerHTTPSEnable {
		logging.Std.Println("Starting HTTPS server...")
		go router.StartHTTPS(quitErrChan, EventChan)
	}
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

			logging.LogChan <- ev
		}
	}
}
