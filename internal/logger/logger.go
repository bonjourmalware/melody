package logger

import (
	"log"
	"os"
)

var (
	Std = log.New(os.Stderr, "", 1)
)

type Logger struct {
	File *os.File
}
