package rules

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
)

type RawReversableValue string

type ReversableValue struct {
	Not bool
	Nocase        bool
	Exact         bool
	CompiledRegex *regexp.Regexp
	ByteValue []byte
}

type ReversableValueList struct {
	Values  []ReversableValue
	Options Options
}

type RawReversableValueList struct {
	Values     []RawReversableValue `yaml:"values"`
	RawOptions []string             `yaml:"options"`
}

func (rvl ReversableValueList) Match(received []byte, rule Rule) bool {
	var contentMatch bool
	var matchCounter int
	var valuesLen = len(rvl.Values)

	for _, ruleValue := range rvl.Values {
		contentMatch = rule.MatchBytesWithOffsetAndDepth(received, ruleValue, rvl.Options)

		// If at least one match in the list, then continue
		//TODO Add "match if at least N content or body rule match"
		if ruleValue.Not {
			contentMatch = !contentMatch
		}

		if rvl.Options.And && !contentMatch {
			return false
		} else if rvl.Options.And && matchCounter < valuesLen {
			matchCounter++
			continue
		} else if contentMatch {
			break
		}
	}

	return contentMatch
}

func (rrv RawReversableValue) Parse() ReversableValue {
	var err error
	var isRegex bool
	rv := ReversableValue{}
	buffer := []byte(rrv)

	// Remove spaces
	buffer = bytes.TrimSpace(buffer)

	modifierMarkerIndex := bytes.IndexByte(buffer[:4], byte(':'))

	if modifierMarkerIndex == 0 {
		fmt.Println("Warning : a leading \":\" will not be taken into account")
	}
	if modifierMarkerIndex != -1 {
		if bytes.ContainsRune(buffer[:modifierMarkerIndex], 'r') {
			isRegex = true
		}
		if bytes.ContainsRune(buffer[:modifierMarkerIndex], 'i') {
			rv.Nocase = true
			buffer = bytes.ToLower(buffer)
		}
		if bytes.ContainsRune(buffer[:modifierMarkerIndex], 'e') {
			rv.Exact = true
		}

		// Remove modifiers
		buffer = append(buffer[:0], buffer[modifierMarkerIndex+1:]...)

		if isRegex {
			rv.CompiledRegex, err = regexp.Compile(string(buffer))
			if err != nil {
				fmt.Println("Failed to compile regex", buffer, ":", err)
				os.Exit(1)
			}
		}
	}

	// Remove eventual spaces left to allow a more instinctive syntax (ie. "ne: not abcd")
	buffer = bytes.TrimSpace(buffer)

	if bytes.HasPrefix(buffer, []byte("not ")) {
		rv.Not = true
		buffer = bytes.Replace(buffer, []byte("not "), []byte{}, 1)
	}

	parsedBuffer, err := ParseHybridPattern(buffer)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rv.ByteValue = parsedBuffer

	return rv
}

func (rrvs RawReversableValueList) Parse() ReversableValueList {
	var rvs ReversableValueList

	rvs.Options = Options{}
	for _, opt := range rrvs.RawOptions {
		switch opt {
		case "and":
			rvs.Options.And = true
		case "nocase":
			rvs.Options.Nocase = true
		case "exact":
			rvs.Options.Exact = true
		default:
			fmt.Println("Unknown option :", opt)
		}
	}

	for _, val := range rrvs.Values {
		var rv ReversableValue
		rv = val.Parse()
		rvs.Values = append(rvs.Values, rv)
	}

	return rvs
}

func ParseHybridPattern(buffer []byte) ([]byte, error) {
	var isHex bool
	var parsedBuffer []byte
	var byteBuffer []byte

	for _, c := range buffer {
		if c == byte('|') {
			// If we already met a '|', then this one is the end delimiter
			// -> Dump the recorded byte buffer and clean it
			if isHex {
				isHex = false

				data, err := hex.DecodeString(string(byteBuffer))
				if err != nil {
					fmt.Println(err)
					continue
				}

				parsedBuffer = append(parsedBuffer, data...)
				byteBuffer = []byte{}
				continue
			} else {
				// Else start recording the bytes until a delimiter is found
				isHex = true
				continue
			}
		} else if isHex {
			// If we already have met a byte delimiter and this char is not a delimiter as well, record as byte
			// Skip spaces in user defined hex string
			if bytes.Compare(byteBuffer, []byte(" ")) == 0 {
				byteBuffer = append(byteBuffer, c)
			}
			continue
		}

		// Register the char as ascii by default
		parsedBuffer = append(parsedBuffer, c)
	}

	if isHex == true {
		return nil, fmt.Errorf("Failed to parse a rule : uneven number of hex delimiter (\"|\") in the rule value %s", buffer)
	}

	return parsedBuffer, nil
}
