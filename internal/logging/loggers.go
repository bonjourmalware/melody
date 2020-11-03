package logging

import (
	"log"
	"os"
	"path/filepath"

	"github.com/bonjourmalware/pinknoise/internal/config"
	"github.com/natefinch/lumberjack"
)

var (
	Sensor   *log.Logger
	Errors   *log.Logger
	Warnings *log.Logger
	Std      *log.Logger
)

func InitLoggers() {
	Std = log.New(os.Stderr, "", log.Ldate|log.Ltime)
	Sensor = log.New(nil, "", 0)
	Errors = log.New(nil, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	Warnings = log.New(nil, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)

	if !*config.Cli.Stdout {
		Sensor.SetOutput(&lumberjack.Logger{
			Filename: filepath.Join(config.Cfg.LogsDir, config.Cfg.LogsSensorFile),
			MaxSize:  config.Cfg.LogsSensorMaxSize,             // megabytes
			MaxAge:   config.Cfg.LogsSensorMaxAge,              //days
			Compress: config.Cfg.LogsSensorCompressRotatedLogs, // disabled by default,
		})
	} else {
		Sensor.SetOutput(os.Stdout)
	}

	if !*config.Cli.Stdout {
		Errors.SetOutput(&lumberjack.Logger{
			Filename: filepath.Join(config.Cfg.LogsDir, config.Cfg.LogsErrorsFile),
			MaxSize:  config.Cfg.LogsErrorsMaxSize,             // megabytes
			MaxAge:   config.Cfg.LogsErrorsMaxAge,              //days
			Compress: config.Cfg.LogsErrorsCompressRotatedLogs, // disabled by default,
		})
	} else {
		Errors.SetOutput(os.Stdout)
	}

	if !*config.Cli.Stdout {
		Warnings.SetOutput(&lumberjack.Logger{
			Filename: filepath.Join(config.Cfg.LogsDir, config.Cfg.LogsErrorsFile),
			MaxSize:  config.Cfg.LogsErrorsMaxSize,             // megabytes
			MaxAge:   config.Cfg.LogsErrorsMaxAge,              //days
			Compress: config.Cfg.LogsErrorsCompressRotatedLogs, // disabled by default,
		})
	} else {
		Warnings.SetOutput(os.Stdout)
	}

}
