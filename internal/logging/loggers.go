package logging

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/bonjourmalware/melody/internal/config"
	"github.com/natefinch/lumberjack"
)

var (
	Sensor   *log.Logger
	Errors   *log.Logger
	Warnings *log.Logger
	Std      *log.Logger
)

func InitLoggers() error {
	Std = log.New(os.Stderr, "", log.Ldate|log.Ltime)
	Sensor = log.New(nil, "", 0)
	Errors = log.New(nil, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	Warnings = log.New(nil, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)

	sensorLogFilepath := filepath.Join(config.Cfg.LogsDir, config.Cfg.LogsSensorFile)
	errorsLogFilepath := filepath.Join(config.Cfg.LogsDir, config.Cfg.LogsErrorsFile)

	if !*config.Cli.Stdout {
		if config.Cfg.LogErrorsEnableRotation {
			Errors.SetOutput(&lumberjack.Logger{
				Filename: filepath.Join(errorsLogFilepath),
				MaxSize:  config.Cfg.LogsErrorsMaxSize,             // megabytes
				MaxAge:   config.Cfg.LogsErrorsMaxAge,              //days
				Compress: config.Cfg.LogsErrorsCompressRotatedLogs, // enabled by default
			})
		} else {
			f, err := os.OpenFile(errorsLogFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("failed to open error log file '%s'", errorsLogFilepath)
			}

			Sensor.SetOutput(f)
		}
	} else {
		Errors.SetOutput(os.Stderr)
	}

	if !*config.Cli.Stdout {
		if config.Cfg.LogErrorsEnableRotation {
			Warnings.SetOutput(&lumberjack.Logger{
				Filename: filepath.Join(errorsLogFilepath),
				MaxSize:  config.Cfg.LogsErrorsMaxSize,             // megabytes
				MaxAge:   config.Cfg.LogsErrorsMaxAge,              //days
				Compress: config.Cfg.LogsErrorsCompressRotatedLogs, // enabled by default
			})
		} else {
			f, err := os.OpenFile(errorsLogFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("failed to open error log file '%s'", errorsLogFilepath)
			}

			Sensor.SetOutput(f)
		}
	} else {
		Warnings.SetOutput(os.Stderr)
	}

	if !*config.Cli.Stdout {
		if config.Cfg.LogSensorEnableRotation {
			Sensor.SetOutput(&lumberjack.Logger{
				Filename: filepath.Join(sensorLogFilepath),
				MaxSize:  config.Cfg.LogsSensorMaxSize,             // megabytes
				MaxAge:   config.Cfg.LogsSensorMaxAge,              //days
				Compress: config.Cfg.LogsSensorCompressRotatedLogs, // enabled by default
			})
		} else {
			f, err := os.OpenFile(sensorLogFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("failed to open sensor log file '%s'", sensorLogFilepath)
			}

			Sensor.SetOutput(f)
		}
	} else {
		Sensor.SetOutput(os.Stdout)
	}

	return nil
}
