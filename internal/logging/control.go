package logging

import (
	"github.com/bonjourmalware/pinknoise/internal/events"
)

var (
	LogChan = make(chan events.Event)
)

func Start(quitErrChan chan error, shutdownChan chan bool, loggerStoppedChan chan bool) {
	go receiveEventsForLogging(quitErrChan, shutdownChan, loggerStoppedChan)
}

func receiveEventsForLogging(quitErrChan chan error, shutdownChan chan bool, loggerStoppedChan chan bool) {
	defer func() {
		close(loggerStoppedChan)
	}()

	for {
		select {

		case ev := <-LogChan:
			logdata, err := ev.ToLog().String()
			if err != nil {
				Warnings.Println("Failed to serialize JSON payload while writing to log file")
				continue
			}

			// Log to sensor file
			Sensor.Println(logdata)

		case <-quitErrChan:
			return

		case <-shutdownChan:
			return
		}
	}
}
