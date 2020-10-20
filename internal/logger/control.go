package logger

import (
	"log"
	"os"

	"github.com/bonjourmalware/pinknoise/internal/events"

	"github.com/natefinch/lumberjack"

	"github.com/bonjourmalware/pinknoise/internal/config"
)

var (
	//TCPIPLoggerChan  = make(chan *events.TCPEvent)
	//HTTPLoggerChan   = make(chan *events.HTTPEvent)
	//ICMPv4LoggerChan = make(chan *events.ICMPv4Event)
	//UDPLoggerChan    = make(chan *events.UDPEvent)
	LogChan = make(chan events.Event)
)

func Start(quitErrChan chan error, shutdownChan chan bool, loggerStoppedChan chan bool) {
	go receiveEventsForLogging(quitErrChan, shutdownChan, loggerStoppedChan)
}

func receiveEventsForLogging(quitErrChan chan error, shutdownChan chan bool, loggerStoppedChan chan bool) {
	log.SetFlags(0)
	if *config.Cli.Stdout == false {
		log.SetOutput(&lumberjack.Logger{
			Filename: config.Cfg.LogFile,
			MaxSize:  config.Cfg.LogMaxSize, // megabytes
			MaxAge:   15,                    //days
			Compress: true,                  // disabled by default,
		})
	} else {
		log.SetOutput(os.Stdout)
	}

	defer func() {
		close(loggerStoppedChan)
	}()

	for {
		select {

		case ev := <-LogChan:
			logdata, err := ev.ToLog().String()
			if err != nil {
				log.Println("failed to serialize JSON payload while writing to log file")
				continue
			}

			log.Println(logdata)

		case <-quitErrChan:
			return

		case <-shutdownChan:
			return
		}
	}
}
