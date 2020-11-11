package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/bonjourmalware/melody/internal/engine"
	"github.com/bonjourmalware/melody/internal/sensor"

	"github.com/bonjourmalware/melody/internal/rules"

	"github.com/bonjourmalware/melody/internal/logging"

	"github.com/bonjourmalware/melody/internal/config"
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

	config.Cli.PcapFilePath = getopt.StringLong("pcap", 'r', "", "Replay a pcap file into the sensor")
	config.Cli.BPF = getopt.StringLong("bpf", 'f', "", "Override the filter.bpf file with the specified filter")
	config.Cli.Interface = getopt.StringLong("interface", 'i', "", "Listen on the specified interface")
	config.Cli.Stdout = getopt.BoolLong("stdout", 's', "Output logged data to stdout instead")
	config.Cli.Dump = getopt.BoolLong("dump", 'd', "Output raw packet details instead of JSON")
	getopt.Parse()

	config.Cfg.Load()
	err := logging.InitLoggers()
	if err != nil {
		logging.Std.Println(err)
		os.Exit(1)
	}
	loaded := rules.LoadRulesDir(config.Cfg.RulesDir)

	logging.Std.Printf("Loaded %d rules\n", loaded)
	logging.Std.Printf("Listing on interface %s\n", config.Cfg.Interface)
}

func main() {
	logging.Std.Println("Starting loggers")
	logging.Start(quitErrChan, shutdownChan, loggerStoppedChan)

	logging.Std.Println("Starting engine")
	engine.Start(quitErrChan, shutdownChan, engineStoppedChan)

	logging.Std.Println("Starting sensor")
	sensor.Start(quitErrChan, shutdownChan, sensorStoppedChan)

	logging.Std.Println("All systems started")

	select {
	case err := <-quitErrChan:
		logging.Errors.Println(err)
		close(shutdownChan)
		break
	case <-quitSigChan:
		close(shutdownChan)
		break
	case <-shutdownChan:
		logging.Std.Println("Shutting down")
		break
	}

	<-sensorStoppedChan
	logging.Std.Println("Sensor stopped")
	<-engineStoppedChan
	logging.Std.Println("Engine stopped")
	<-loggerStoppedChan
	logging.Std.Println("Logger stopped")
	logging.Std.Println("Reached shutdown")
}
