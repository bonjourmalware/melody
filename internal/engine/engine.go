package engine

import (
	"gitlab.com/Alvoras/pinknoise/internal/logger"

	"gitlab.com/Alvoras/pinknoise/internal/events"
)

var (
	TCPEventChan  = make(chan *events.TCPEvent)
	HTTPEventChan   = make(chan *events.HTTPEvent)
	ICMPv4EventChan = make(chan *events.ICMPv4Event)
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
		case ev := <-TCPEventChan:
			qualifyTCPEvent(ev)
			logger.TCPIPLoggerChan <- ev

		case ev := <-HTTPEventChan:
			qualifyHTTPEvent(ev)
			logger.HTTPLoggerChan <- ev

		case ev := <-ICMPv4EventChan:
			qualifyICMPv4Event(ev)
			logger.ICMPv4LoggerChan <- ev

		default:
		}
	}
}