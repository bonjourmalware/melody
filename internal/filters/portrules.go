package filters

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bonjourmalware/pinknoise/internal/logging"
)

type PortRanges []PortRange

type PortRules struct {
	WhitelistedPorts PortRanges
	BlacklistedPorts PortRanges
}

type PortRange struct {
	Lower uint16
	Upper uint16
}

func NewPortRange(lower uint16, upper uint16) PortRange {
	return PortRange{
		Lower: lower,
		Upper: upper,
	}
}

func (prls *PortRules) ParseRules(whitelist []string, blacklist []string) {
	for _, rawRule := range whitelist {
		rule := strings.Replace(rawRule, " ", "", -1)

		if strings.Contains(rule, "-") {
			err := prls.WhitelistRange(rule)
			if err != nil {
				logging.Errors.Println(fmt.Sprintf("Failed to parse the Port rule [%s]:", rule))
				logging.Errors.Println(err)
				os.Exit(1)
			}
		} else {
			err := prls.Whitelist(rule)
			if err != nil {
				logging.Errors.Println(fmt.Sprintf("Failed to parse the Port rule [%s]:", rule))
				logging.Errors.Println(err)
				os.Exit(1)
			}
		}
	}

	for _, rawRule := range blacklist {
		rule := strings.Replace(rawRule, " ", "", -1)

		if strings.Contains(rule, "-") {
			err := prls.BlacklistRange(rule)
			if err != nil {
				logging.Errors.Println(fmt.Sprintf("Failed to parse the Port rule [%s]:", rule))
				logging.Errors.Println(err)
				os.Exit(1)
			}
			continue
		}

		err := prls.Blacklist(rule)
		if err != nil {
			logging.Errors.Println(fmt.Sprintf("Failed to parse the Port rule [%s]:", rule))
			logging.Errors.Println(err)
			os.Exit(1)
		}
		continue
	}

	prls.BlacklistedPorts.MergeOverlapping()
	prls.WhitelistedPorts.MergeOverlapping()
}

// PortRanges methods
func (prgs *PortRanges) MergeOverlapping() {
	workSlice := make(PortRanges, len(*prgs))
	copy(workSlice, *prgs)

	for i := 0; i < len(workSlice); i++ {
		for idx, candidate := range workSlice {
			if candidate.Equals(workSlice[i]) {
				// Skip
				continue
			}

			if candidate.ContainsPortRange(workSlice[i]) {
				workSlice.RemoveAt(i)
				i = 0 // Restart upper loop
				break
			}

			if workSlice[i].ContainsPortRange(candidate) {
				workSlice.RemoveAt(idx)
				i = 0 // Restart upper loop
				break
			}

			if candidate.ContainsPortNotEqual(workSlice[i].Lower) && !candidate.ContainsPortNotEqual(workSlice[i].Upper) {
				// Replace the candidate's upper with the current's upper
				workSlice[idx].Upper = workSlice[i].Upper
				workSlice.RemoveAt(i)
				i = 0 // Restart upper loop
				break
			}

			if candidate.ContainsPortNotEqual(workSlice[i].Upper) && !candidate.ContainsPortNotEqual(workSlice[i].Lower) {
				// Replace the candidate's lower with the current's lower
				workSlice[idx].Lower = workSlice[i].Lower
				workSlice.RemoveAt(i)
				i = 0 // Restart upper loop
				break
			}
		}
	}

	*prgs = workSlice
}

func (prgs *PortRanges) RemoveAt(index int) {
	workSlice := make(PortRanges, len(*prgs))
	copy(workSlice, *prgs)

	workSlice = append(workSlice[:index], workSlice[index+1:]...)
	*prgs = workSlice
}

func (prgs *PortRanges) Add(port uint16) {
	portRange := NewPortRange(port, port)
	*prgs = append(*prgs, portRange)
}

func (prgs *PortRanges) AddRange(lower uint16, upper uint16) {
	ipr := NewPortRange(lower, upper)
	*prgs = append(*prgs, ipr)
}

// PortRange methods
func (prg PortRange) ContainsPort(port uint16) bool {
	if port >= prg.Lower && port <= prg.Upper {
		return true
	}

	return false
}

func (prg PortRange) ContainsPortRange(portRange PortRange) bool {
	if prg.ContainsPort(portRange.Lower) && portRange.ContainsPort(portRange.Upper) {
		return true
	}

	return false
}

func (prg PortRange) ContainsPortNotEqual(port uint16) bool {
	if prg.Lower != port && prg.Upper != port {
		return true
	}

	return false
}

func (prg *PortRange) Equals(portRange PortRange) bool {
	return prg.Upper == portRange.Upper && prg.Lower == portRange.Lower
}

// Ranges
func (prls *PortRules) WhitelistRange(rawPortRange string) error {
	portFrom, portTo, err := parseRawPortRange(rawPortRange)
	if err != nil {
		return err
	}

	prls.WhitelistedPorts.AddRange(portFrom, portTo)

	return nil
}

func (prls *PortRules) BlacklistRange(rawPortRange string) error {
	portFrom, portTo, err := parseRawPortRange(rawPortRange)
	if err != nil {
		return err
	}

	prls.BlacklistedPorts.AddRange(portFrom, portTo)

	return nil
}

func parseRawPortRange(rawPortRange string) (uint16, uint16, error) {
	var portFrom uint16
	var portTo uint16
	var err error

	hostRange := strings.Split(rawPortRange, "-")

	lower, higher := hostRange[0], hostRange[1]

	portFrom, err = parsePortString(lower)
	if err != nil {
		return portFrom, portTo, err
	}

	portTo, err = parsePortString(higher)
	if err != nil {
		return portFrom, portTo, err
	}

	return portFrom, portTo, err
}

// Single Ports
func (prls *PortRules) Whitelist(port string) error {
	parsed, err := parsePortString(port)
	if err != nil {
		return err
	}

	prls.WhitelistedPorts.Add(parsed)
	return nil
}

func (prls *PortRules) Blacklist(port string) error {
	parsed, err := parsePortString(port)
	if err != nil {
		return err
	}

	prls.BlacklistedPorts.Add(parsed)
	return nil
}

func parsePortString(port string) (uint16, error) {
	parsed, err := strconv.ParseUint(port, 10, 64)
	if err != nil {
		return uint16(parsed), err
	}

	if parsed < 0 || parsed > 65535 {
		return uint16(parsed), fmt.Errorf("Port %s must be between 0 and 65535\n", port)
	}

	return uint16(parsed), nil
}
