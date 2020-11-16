package clihelper

import (
	"strings"

	"github.com/pborman/getopt/v2"
)

type MultiString []string

func (h *MultiString) Set(str string, opt getopt.Option) error {
	*h = append(*h, str)
	_ = opt
	return nil
}

func (h *MultiString) String() string {
	return strings.Join(h.Array(), ", ")
}

func (h *MultiString) Array() []string {
	return *h
}

func (h *MultiString) ParseMultipleOptions() []string {
	return h.Array()
}
