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
		if _, err := os.Stat(config.Cfg.LogsDir); os.IsNotExist(err) {
			if err := os.Mkdir(config.Cfg.LogsDir, 0755); err != nil {
				return fmt.Errorf("failed to create log directory : %s", err)
			}
		}

		_, err := os.Stat(errorsLogFilepath)
		if os.IsNotExist(err) {
			if _, err := os.Create(errorsLogFilepath); err != nil {
				return fmt.Errorf("failed to create error log file : %s", err)
			}
		}else{
			return fmt.Errorf("failed to create error log file : %s", err)
		}

		_, err = os.Stat(sensorLogFilepath)
		if os.IsNotExist(err) {
			if _, err := os.Create(sensorLogFilepath); err != nil {
				return fmt.Errorf("failed to create error log file : %s", err)
			}
		}else{
			return fmt.Errorf("failed to create error log file : %s", err)
		}

		if config.Cfg.LogErrorsEnableRotation {
			Errors.SetOutput(&lumberjack.Logger{
				Filename: filepath.Join(errorsLogFilepath),
				MaxSize:  config.Cfg.LogsErrorsMaxSize,             // megabytes
				MaxAge:   config.Cfg.LogsErrorsMaxAge,              //days
				Compress: config.Cfg.LogsErrorsCompressRotatedLogs, // enabled by default
			})

			Warnings.SetOutput(&lumberjack.Logger{
				Filename: filepath.Join(errorsLogFilepath),
				MaxSize:  config.Cfg.LogsErrorsMaxSize,             // megabytes
				MaxAge:   config.Cfg.LogsErrorsMaxAge,              // days
				Compress: config.Cfg.LogsErrorsCompressRotatedLogs, // enabled by default
			})
		} else {
			errorsFile, err := os.OpenFile(errorsLogFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("failed to open error log file : %s", err)
			}

			Errors.SetOutput(errorsFile)
			Warnings.SetOutput(errorsFile)
		}

		if config.Cfg.LogSensorEnableRotation {
			Sensor.SetOutput(&lumberjack.Logger{
				Filename: filepath.Join(sensorLogFilepath),
				MaxSize:  config.Cfg.LogsSensorMaxSize,             // megabytes
				MaxAge:   config.Cfg.LogsSensorMaxAge,              // days
				Compress: config.Cfg.LogsSensorCompressRotatedLogs, // enabled by default
			})
		} else {
			sensorFile, err := os.OpenFile(sensorLogFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("failed to open sensor log file : %s", err)
			}

			Sensor.SetOutput(sensorFile)
		}
	} else {
		Errors.SetOutput(os.Stderr)
		Sensor.SetOutput(os.Stdout)
		Warnings.SetOutput(os.Stderr)
	}

	//if !*config.Cli.Stdout {
	//	if config.Cfg.LogErrorsEnableRotation {
	//	} else {
	//		f, err := os.OpenFile(errorsLogFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	//		if err != nil {
	//			return fmt.Errorf("failed to open error log file %: s", errorsLogFilepa err
	//		}
	//
	//		Sensor.SetOutput(f)
	//	}
	//}
	//
	//if !*config.Cli.Stdout {
	//	if config.Cfg.LogSensorEnableRotation {
	//		Sensor.SetOutput(&lumberjack.Logger{
	//			Filename: filepath.Join(sensorLogFilepath),
	//			MaxSize:  config.Cfg.LogsSensorMaxSize,             // megabytes
	//			MaxAge:   config.Cfg.LogsSensorMaxAge,              // days
	//			Compress: config.Cfg.LogsSensorCompressRotatedLogs, // enabled by default
	//		})
	//	} else {
	//		f, err := os.OpenFile(sensorLogFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	//		if err != nil {
	//			return fmt.Errorf("failed to open sensor log file '%s'", sensorLogFilepath)
	//		}
	//
	//		Sensor.SetOutput(f)
	//	}
	//}

	return nil
}
