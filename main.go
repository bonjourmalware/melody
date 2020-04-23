package main

import (
	"fmt"
	"gitlab.com/Alvoras/pinknoise/internal/rules"
	"os"
	"os/signal"
	"syscall"

	"gitlab.com/Alvoras/pinknoise/internal/logger"
	"gitlab.com/Alvoras/pinknoise/internal/sensor"

	"github.com/pborman/getopt"
	"gitlab.com/Alvoras/pinknoise/internal/config"
	"gitlab.com/Alvoras/pinknoise/internal/engine"
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

	config.Cli.PcapFilePath = getopt.StringLong("pcap", 'f', "", "Replay a pcap file into the honeypot")
	config.Cli.Interface = getopt.StringLong("interface", 'i', "", "Listen on the specified interface")
	config.Cli.HomeNet = getopt.ListLong("homenet", 'n', "Overrides the HomeNet values")
	config.Cli.Stdout = getopt.BoolLong("stdout", 's', "", "Output logged data to stdout instead")
	getopt.Parse()

	config.Cfg.Load()
	rules.LoadRulesDir(config.Cfg.RulesDir)
}

func main() {
	//eventChan := make(chan *events.Event)
	//loggerChan := make(chan *events.Event)

	logger.Start(quitErrChan, shutdownChan, loggerStoppedChan)
	engine.Start(quitErrChan, shutdownChan, engineStoppedChan)
	sensor.Start(quitErrChan, shutdownChan, sensorStoppedChan)

	fmt.Println("All system started")

	select {
	case err := <-quitErrChan:
		fmt.Println(err)
		close(shutdownChan)
		break
	case <-quitSigChan:
		close(shutdownChan)
		break
	case <-shutdownChan:
		fmt.Println("Shutting down...")
		break
	}

	<-sensorStoppedChan
	<-engineStoppedChan
	<-loggerStoppedChan

	fmt.Println("Exited")
}
