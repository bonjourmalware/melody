package engine

import (
	"github.com/bonjourmalware/pinknoise/internal/events"
	"github.com/bonjourmalware/pinknoise/internal/logger"
	"github.com/bonjourmalware/pinknoise/internal/rules"
)

var (
	//TCPEventChan  = make(chan *events.TCPEvent)
	//HTTPEventChan   = make(chan *events.HTTPEvent)
	//ICMPv4EventChan = make(chan *events.ICMPv4Event)
	//UDPEventChan = make(chan *events.UDPEvent)
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
		case ev := <-EventChan:
			//ev.Qualify()
			var matches []rules.Rule

			for _, ruleset := range rules.GlobalRules {
				for _, rule := range ruleset {
					if rule.Layer != ev.GetKind() {
						continue
					}
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

		//case ev := <-TCPEventChan:
		//	qualifyTCPEvent(ev)
		//	logger.TCPIPLoggerChan <- ev
		//
		//case ev := <-HTTPEventChan:
		//	qualifyHTTPEvent(ev)
		//	logger.HTTPLoggerChan <- ev
		//
		//case ev := <-ICMPv4EventChan:
		//	qualifyICMPv4Event(ev)
		//	logger.ICMPv4LoggerChan <- ev
		//
		//case ev := <-UDPEventChan:
		//	qualifyUDPEvent(ev)
		//	logger.UDPLoggerChan <- ev

		default:
		}
	}
}
