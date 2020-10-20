package main

import (
	"github.com/bonjourmalware/pinknoise/internal/engine"
	"os"
	"os/signal"
	"syscall"

	"github.com/bonjourmalware/pinknoise/internal/rules"

	"github.com/bonjourmalware/pinknoise/internal/logger"
	"github.com/bonjourmalware/pinknoise/internal/sensor"

	"github.com/pborman/getopt"
	"github.com/bonjourmalware/pinknoise/internal/config"
)

var (
	quitErrChan       = make(chan error)
	shutdownChan      = make(chan bool)
	loggerStoppedChan = make(chan bool)
	engineStoppedChan = make(chan bool)
	sensorStoppedChan = make(chan bool)
	quitSigChan       = make(chan os.Signal, 1)
)

func init() {
	signal.Notify(quitSigChan, syscall.SIGINT, syscall.SIGTERM)

	config.Cli.PcapFilePath = getopt.StringLong("pcap", 'r', "", "Replay a pcap file into the honeypot")
	config.Cli.Interface = getopt.StringLong("interface", 'i', "", "Listen on the specified interface")
	config.Cli.HomeNet = getopt.ListLong("homenet", 'n', "Overrides the HomeNet values")
	config.Cli.HomeNet6 = getopt.ListLong("homenet6", 'N', "Overrides the HomeNet6 values")
	config.Cli.Stdout = getopt.BoolLong("stdout", 's', "", "Output logged data to stdout instead")
	config.Cli.Dump = getopt.BoolLong("dump", 'd', "", "Display packet details")
	getopt.Parse()

	config.Cfg.Load()
	rules.LoadRulesDir(config.Cfg.RulesDir)
}

func main() {
	//eventChan := make(chan *events.BaseEvent)
	//loggerChan := make(chan *events.BaseEvent)

	logger.Start(quitErrChan, shutdownChan, loggerStoppedChan)
	engine.Start(quitErrChan, shutdownChan, engineStoppedChan)
	sensor.Start(quitErrChan, shutdownChan, sensorStoppedChan)

	logger.Std.Println("All systems started")

	select {
	case err := <-quitErrChan:
		logger.Std.Println(err)
		close(shutdownChan)
		break
	case <-quitSigChan:
		close(shutdownChan)
		break
	case <-shutdownChan:
		logger.Std.Println("Shutting down...")
		break
	}

	<-sensorStoppedChan
	<-engineStoppedChan
	<-loggerStoppedChan

	logger.Std.Println("Exited")
}
