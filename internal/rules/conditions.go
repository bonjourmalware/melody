package rules

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/bonjourmalware/pinknoise/internal/logger"
)

type RawConditions struct {
	Groups    map[string][]string `yaml:"-,inline"`
	MatchType string              `yaml:"match"`
}

//type RawConditions map[string][]string

type ConditionsList struct {
	Conditions []Conditions
	MatchAll   bool
	MatchAny   bool
}

type Conditions struct {
	Values  []ConditionValue
	Options Options
}

type Options struct {
	Nocase     bool
	Is         bool
	All        bool
	Contains   bool
	Startswith bool
	Endswith   bool
	Regex      bool
}

type ConditionValue struct {
	CompiledRegex *regexp.Regexp
	ByteValue     []byte
}

func (condList ConditionsList) Match(received []byte, ruleOptions RuleOptions) bool {
	if condList.Conditions != nil {
		if condList.MatchAny {
			var condOK = false
			for _, condGroup := range condList.Conditions {
				// If any condition group is valid, continue
				if condGroup.Match(received, ruleOptions) == true {
					condOK = true
					break
				}
			}

			if !condOK {
				return false
			}
		} else { // condList.MatchAll
			for _, condGroup := range condList.Conditions {
				// If any condition group is invalid, rule is false
				// Continue if the test for all the values are successful
				if condGroup.Match(received, ruleOptions) == false {
					return false
				}
			}
		}
	}

	return true
}

func (cond Conditions) Match(received []byte, ruleOptions RuleOptions) bool {
	var contentMatch bool
	var matchCounter int
	var valuesLen = len(cond.Values)

	for _, condVal := range cond.Values {
		contentMatch = cond.MatchBytesWithOptions(received, condVal, ruleOptions)

		if cond.Options.All && !contentMatch {
			return false
			//	Continue unless all the tests passed
		} else if cond.Options.All && matchCounter < valuesLen {
			matchCounter++
			continue
		} else if contentMatch {
			// If at least one match in the list, then continue
			break
		}
	}

	return contentMatch
}

// This function only cares about the matching modifier ("contains", "startswith", etc, not "all")
// The condition's options are being taken care of in the Conditions.Match function
func (cond Conditions) MatchBytesWithOptions(received []byte, condVal ConditionValue, ruleOptions RuleOptions) bool {
	var match bool
	var condValContent = condVal.ByteValue

	if cond.Options.Nocase {
		received = bytes.ToLower(received)
		condValContent = bytes.ToLower(condValContent)
	}

	if ruleOptions.Offset > 0 && ruleOptions.Offset < len(received) {
		received = received[ruleOptions.Offset:]
	}

	if ruleOptions.Depth > 0 && ruleOptions.Depth < len(received) {
		received = received[:ruleOptions.Depth]
	}

	if cond.Options.Is {
		match = bytes.Compare(received, condValContent) == 0
	} else if cond.Options.Regex {
		match = condVal.CompiledRegex.Match(received)
	} else if cond.Options.Contains {
		match = bytes.Contains(received, condValContent)
	} else if cond.Options.Startswith {
		match = bytes.HasPrefix(received, condValContent)
	} else if cond.Options.Endswith {
		match = bytes.HasSuffix(received, condValContent)
	}
	return match
}

func (condsList *ConditionsList) ParseMatchType(matchType string, ruleId string) {
	switch matchType {
	case "any":
		condsList.MatchAny = true
	case "all":
		condsList.MatchAll = true
	}

	if !condsList.MatchAny && !condsList.MatchAll {
		logger.Std.Printf("No match behaviour defined for rule %s, defaulting to \"any\"\n", ruleId)
		condsList.MatchAny = true
	}
}

func (rawCondList RawConditions) ParseList(ruleId string) *ConditionsList {
	if len(rawCondList.Groups) == 0 {
		return nil
	}

	condsList := ConditionsList{}
	var bufCond Conditions

	for options, val := range rawCondList.Groups {
		bufCond = Conditions{}
		err := bufCond.ParseOptions(options)
		if err != nil {
			log.Printf("Failed to parse rule %s : %s\n", ruleId, err)
			return &ConditionsList{}
		}
		bufCond.ParseValues(val)
		condsList.Conditions = append(condsList.Conditions, bufCond)
	}

	condsList.ParseMatchType(rawCondList.MatchType, ruleId)

	return &condsList
}

func (cond *Conditions) ParseOptions(opt string) error {
	chunks := strings.Split(opt, "|")
	modeQty := 0
	var newOption Options

	if opt == "" {
		return fmt.Errorf("options parsing failed for condition %s : matching mode cannot be empty\n", opt)
	}

	for _, chunk := range chunks {
		switch chunk {
		case "all":
			newOption.All = true
		case "nocase":
			newOption.Nocase = true
		case "regex":
			newOption.Regex = true
		case "is":
			modeQty++
			newOption.Is = true
		case "contains":
			modeQty++
			newOption.Contains = true
		case "startswith":
			modeQty++
			newOption.Startswith = true
		case "endswith":
			modeQty++
			newOption.Endswith = true
		default:
			return fmt.Errorf("options parsing failed for condition %s : unknown option \"%s\"\n", opt, chunk)
		}
	}

	if modeQty > 1 {
		return fmt.Errorf("options parsing failed for condition %s : there can only be one of <is|contains|startswith|endswith>\n", opt)
	}

	cond.Options = newOption

	return nil
}

func (cond *Conditions) ParseValues(list []string) {
	var err error
	var condValBuf = ConditionValue{}

	for _, val := range list {
		buffer := []byte(val)

		condValBuf = ConditionValue{}
		if cond.Options.Regex {
			condValBuf.CompiledRegex, err = regexp.Compile(val)
			if err != nil {
				log.Println("Failed to compile regex", val, ":", err)
				os.Exit(1)
			}
		}
		parsedBuffer, err := ParseHybridPattern(buffer)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		condValBuf.ByteValue = parsedBuffer

		cond.Values = append(cond.Values, condValBuf)
	}
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
					return nil, fmt.Errorf("failed to parse hybrid pattern : [%s] in %s", err, buffer)
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
			if c == ' ' {
				continue
			}
			byteBuffer = append(byteBuffer, c)
		} else {
			parsedBuffer = append(parsedBuffer, c)
		}
	}

	if isHex == true {
		return nil, fmt.Errorf("failed to parse hybrid pattern : uneven number of hex delimiter (\"|\") in %s", buffer)
	}

	return parsedBuffer, nil
}
