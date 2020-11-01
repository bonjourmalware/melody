package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/bonjourmalware/pinknoise/internal/engine"
	"github.com/bonjourmalware/pinknoise/internal/sensor"

	"github.com/bonjourmalware/pinknoise/internal/rules"

	"github.com/bonjourmalware/pinknoise/internal/logging"

	"github.com/bonjourmalware/pinknoise/internal/config"
	"github.com/pborman/getopt"
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
	config.Cli.Stdout = getopt.BoolLong("stdout", 's', "Output logged data to stdout instead")
	config.Cli.Dump = getopt.BoolLong("dump", 'd', "Output raw packet details instead of JSON")
	getopt.Parse()

	config.Cfg.Load()

	logging.InitLoggers()
	rules.LoadRulesDir(config.Cfg.RulesDir)
}

func main() {
	logging.Start(quitErrChan, shutdownChan, loggerStoppedChan)
	engine.Start(quitErrChan, shutdownChan, engineStoppedChan)
	sensor.Start(quitErrChan, shutdownChan, sensorStoppedChan)

	logging.Std.Println("All systems started")

	select {
	case err := <-quitErrChan:
		logging.Std.Println(err)
		close(shutdownChan)
		break
	case <-quitSigChan:
		close(shutdownChan)
		break
	case <-shutdownChan:
		logging.Std.Println("Shutting down...")
		break
	}

	<-sensorStoppedChan
	<-engineStoppedChan
	<-loggerStoppedChan

	logging.Std.Println("Exited")
}
