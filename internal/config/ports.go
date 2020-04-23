package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type EnabledPorts [65535]bool

func (p *EnabledPorts) IsActivePort(port int) bool {
	if !isValidPort(port) {
		return false
	}

	return p[port-1]
}

func (p *EnabledPorts) ParseRules(rules []string) {
	for _, rawRule := range rules {
		rule := strings.Replace(rawRule, " ", "", -1)

		if strings.HasPrefix(rawRule, "not") {
			rule = strings.TrimPrefix(rule, "not")

			if strings.Contains(rule, "-") {
				err := p.RemoveRange(rule)
				if err != nil {
					fmt.Println(fmt.Sprintf("Failed to parse a port rule [%s]", rule))
					//fmt.Println(err)
					os.Exit(1)
				}
				continue
			}

			err := p.Remove(rule)
			if err != nil {
				fmt.Println(fmt.Sprintf("Failed to parse a port rule [%s]", rule))
				//fmt.Println(err)
				os.Exit(1)
			}
			continue
		}

		if strings.Contains(rule, "-") {
			err := p.AddRange(rule)
			if err != nil {
				fmt.Println(fmt.Sprintf("Failed to parse a port rule [%s]", rule))
				//fmt.Println(err)
				os.Exit(1)
			}
		} else {
			err := p.Add(rule)
			if err != nil {
				fmt.Println(fmt.Sprintf("Failed to parse a port rule [%s]", rule))
				//fmt.Println(err)
				os.Exit(1)
			}
		}
	}
}

func (p *EnabledPorts) AddRange(rawPortRange string) error {
	portRange := strings.Split(rawPortRange, "-")

	from, to := portRange[0], portRange[1]

	iFrom, err := strconv.Atoi(from)
	if err != nil {
		return err
	}

	iTo, err := strconv.Atoi(to)
	if err != nil {
		return err
	}

	checkValidPortRange(iFrom, iTo)

	for i := iFrom - 1; i < iTo; i++ {
		p[i] = true
	}

	return nil
}

func (p *EnabledPorts) RemoveRange(rawPortRange string) error {
	portRange := strings.Split(rawPortRange, "-")

	from, to := portRange[0], portRange[1]

	iFrom, err := strconv.Atoi(from)
	if err != nil {
		return err
	}

	iTo, err := strconv.Atoi(to)
	if err != nil {
		return err
	}

	checkValidPortRange(iFrom, iTo)

	for i := iFrom - 1; i < iTo; i++ {
		p[i] = false
	}

	return nil
}

func (p *EnabledPorts) Add(port string) error {
	iPort, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	checkValidPort(iPort)

	p[iPort-1] = true

	return nil
}

func (p *EnabledPorts) Remove(port string) error {
	iPort, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	checkValidPort(iPort)

	p[iPort-1] = false

	return nil
}

func checkValidPort(port int) {
	if !isValidPort(port) {
		fmt.Println(fmt.Sprintf("[%d] is not a valid port", port))
		os.Exit(1)
	}
}

func checkValidPortRange(from int, to int) {
	if !isValidPortRange(from, to) {
		fmt.Println(fmt.Sprintf("[%d - %d] is not a valid port range", from, to))
		os.Exit(1)
	}
}

func isValidPort(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}

	return true
}

func isValidPortRange(from int, to int) bool {
	if from > to {
		return false
	} else if !isValidPort(from) || !isValidPort(to) {
		return false
	}

	return true
}
