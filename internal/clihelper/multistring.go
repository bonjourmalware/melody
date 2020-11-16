package clihelper

import (
	"strings"

	"github.com/pborman/getopt/v2"
)

// MultiString is a getopt Option to allows passing multiple of the same option and get an array of values
// Example : -o "a" -o "b" -o "c" -> [a, b, c]
type MultiString []string

// Set is the method called when the parser encounters a matching switch
func (h *MultiString) Set(str string, opt getopt.Option) error {
	*h = append(*h, str)
	_ = opt
	return nil
}

// String is an helper to get the string representation of the option
func (h *MultiString) String() string {
	return strings.Join(h.Array(), ", ")
}

// Array returns the values as an array
func (h *MultiString) Array() []string {
	return *h
}

// ParseMultipleOptions returns the values parsed as an array
func (h *MultiString) ParseMultipleOptions() []string {
	return h.Array()
}
