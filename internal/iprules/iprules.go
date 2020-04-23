package iprules

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
)

type IPRanges []IPRange

type IPRules struct {
	WhitelistedIPs IPRanges
	BlacklistedIPs IPRanges
}

type IPRange struct {
	Lower net.IP
	Upper net.IP
}

func NewIPRange(lower net.IP, upper net.IP) IPRange {
	return IPRange{
		Lower: lower,
		Upper: upper,
	}
}

func (iprl *IPRules) ParseRules(rules []string) {
	for _, rawRule := range rules {
		rule := strings.Replace(rawRule, " ", "", -1)

		if strings.HasPrefix(rawRule, "not") {
			rule = strings.TrimPrefix(rule, "not")

			if strings.Contains(rule, "-") {
				err := iprl.BlacklistRange(rule)
				if err != nil {
					fmt.Println(fmt.Sprintf("Failed to parse the IP rule [%s]:", rule))
					fmt.Println(err)
					os.Exit(1)
				}
				continue
			} else if strings.Contains(rule, "/") {
				err := iprl.BlacklistCIDR(rule)
				if err != nil {
					fmt.Println(fmt.Sprintf("Failed to parse the IP rule [%s]:", rule))
					fmt.Println(err)
					os.Exit(1)
				}
				continue
			}

			err := iprl.Blacklist(rule)
			if err != nil {
				fmt.Println(fmt.Sprintf("Failed to parse the IP rule [%s]:", rule))
				//fmt.Println(err)
				os.Exit(1)
			}
			continue
		}

		if strings.Contains(rule, "-") {
			err := iprl.WhitelistRange(rule)
			if err != nil {
				fmt.Println(fmt.Sprintf("Failed to parse the IP rule [%s]:", rule))
				fmt.Println(err)
				os.Exit(1)
			}
		} else if strings.Contains(rule, "/") {
			err := iprl.WhitelistCIDR(rule)
			if err != nil {
				fmt.Println(fmt.Sprintf("Failed to parse the IP rule [%s]:", rule))
				//fmt.Println(err)
				os.Exit(1)
			}
			continue
		} else {
			err := iprl.Whitelist(rule)
			if err != nil {
				fmt.Println(fmt.Sprintf("Failed to parse the IP rule [%s]:", rule))
				fmt.Println(err)
				os.Exit(1)
			}
		}
	}

	iprl.BlacklistedIPs.MergeOverlapping()
	iprl.WhitelistedIPs.MergeOverlapping()
}

// IPRanges methods
func (iprgs *IPRanges) MergeOverlapping() {
	workSlice := make(IPRanges, len(*iprgs))
	copy(workSlice, *iprgs)

	for i := 0; i < len(workSlice); i++ {
		for idx, candidate := range workSlice {
			if candidate.Equals(workSlice[i]) {
				// Skip
				continue
			}

			if candidate.ContainsIPRange(workSlice[i]) {
				workSlice.RemoveAt(i)
				i = 0 // Restart upper loop
				break
			}

			if workSlice[i].ContainsIPRange(candidate) {
				workSlice.RemoveAt(idx)
				i = 0 // Restart upper loop
				break
			}

			if candidate.ContainsIPNotEqual(workSlice[i].Lower) && !candidate.ContainsIPNotEqual(workSlice[i].Upper) {
				// Replace the candidate's upper with the current's upper
				workSlice[idx].Upper = workSlice[i].Upper
				workSlice.RemoveAt(i)
				i = 0 // Restart upper loop
				break
			}

			if candidate.ContainsIPNotEqual(workSlice[i].Upper) && !candidate.ContainsIPNotEqual(workSlice[i].Lower) {
				// Replace the candidate's lower with the current's lower
				workSlice[idx].Lower = workSlice[i].Lower
				workSlice.RemoveAt(i)
				i = 0 // Restart upper loop
				break
			}
		}
	}

	*iprgs = workSlice
}

func (iprgs *IPRanges) RemoveAt(index int) {
	workSlice := make(IPRanges, len(*iprgs))
	copy(workSlice, *iprgs)

	workSlice = append(workSlice[:index], workSlice[index+1:]...)
	*iprgs = workSlice
}

func (iprgs *IPRanges) Add(ip net.IP) {
	ipr := NewIPRange(ip, ip)
	*iprgs = append(*iprgs, ipr)
}

func (iprgs *IPRanges) AddString(ipstr string) error {
	var ip net.IP

	if val := net.ParseIP(ipstr); val != nil {
		ip = val
	} else {
		return fmt.Errorf("invalid IP [%s]", ipstr)
	}

	iprgs.Add(ip.To4())

	return nil
}

func (iprgs *IPRanges) AddRange(lower net.IP, upper net.IP) {
	ipr := NewIPRange(lower, upper)
	*iprgs = append(*iprgs, ipr)
}

// IPRange methods
func (iprg IPRange) ContainsIPString(ipstr string) bool {
	var ip net.IP
	if val := net.ParseIP(ipstr); val != nil {
		ip = val
	} else {
		return false
	}

	return iprg.ContainsIP(ip)
}

func (iprg IPRange) ContainsIP(ip net.IP) bool {
	if bytes.Compare(ip.To4(), iprg.Lower) >= 0 && bytes.Compare(ip.To4(), iprg.Upper) <= 0 {
		return true
	}

	return false
}

func (iprg IPRange) ContainsIPRange(iprange IPRange) bool {
	if iprg.ContainsIP(iprange.Lower.To4()) && iprange.ContainsIP(iprange.Upper.To4()) {
		return true
	}

	return false
}

func (iprg IPRange) ContainsIPNotEqual(ip net.IP) bool {
	if !bytes.Equal(ip.To4(), iprg.Lower) && !bytes.Equal(ip.To4(), iprg.Upper) {
		return true
	}

	return false
}

func (iprg *IPRange) Equals(iprange IPRange) bool {
	return bytes.Equal(iprg.Upper, iprange.Upper.To4()) && bytes.Equal(iprg.Lower, iprange.Lower.To4())
}

// CIDR
func (iprl *IPRules) WhitelistCIDR(rawIPCIDR string) error {
	ipFrom, ipnet, err := net.ParseCIDR(rawIPCIDR)
	if err != nil {
		return err
	}

	ipFrom, ipTo, err := AddressRange(ipnet)
	if err != nil {
		return err
	}

	iprl.WhitelistedIPs.AddRange(ipFrom, ipTo)

	return nil
}

func (iprl *IPRules) BlacklistCIDR(rawIPCIDR string) error {
	ipFrom, ipnet, err := net.ParseCIDR(rawIPCIDR)
	if err != nil {
		return err
	}

	ipFrom, ipTo, err := AddressRange(ipnet)
	if err != nil {
		return err
	}

	iprl.BlacklistedIPs.AddRange(ipFrom, ipTo)

	return nil
}

// Ranges
func (iprl *IPRules) WhitelistRange(rawIPRange string) error {
	var ipFrom net.IP
	var ipTo net.IP

	hostRange := strings.Split(rawIPRange, "-")

	lower, higher := hostRange[0], hostRange[1]

	if val := net.ParseIP(lower); val != nil {
		ipFrom = val
	} else {
		return fmt.Errorf("[%s-%s] is not a valid IP address range", lower, higher)
	}

	if val := net.ParseIP(higher); val != nil {
		ipTo = val
	} else {
		return fmt.Errorf("[%s-%s] is not a valid IP address range", lower, higher)
	}

	checkValidIPRange(ipFrom, ipTo)

	iprl.WhitelistedIPs.AddRange(ipFrom, ipTo)

	return nil
}

func (iprl *IPRules) BlacklistRange(rawIPRange string) error {
	var ipFrom net.IP
	var ipTo net.IP

	hostRange := strings.Split(rawIPRange, "-")

	lower, higher := hostRange[0], hostRange[1]

	if val := net.ParseIP(lower); val != nil {
		ipFrom = val
	} else {
		return fmt.Errorf("[%s-%s] is not a valid IP address range", lower, higher)
	}

	if val := net.ParseIP(higher); val != nil {
		ipTo = val
	} else {
		return fmt.Errorf("[%s-%s] is not a valid IP address range", lower, higher)
	}

	checkValidIPRange(ipFrom, ipTo)

	iprl.BlacklistedIPs.AddRange(ipFrom, ipTo)

	return nil
}

// Single IPs
func (iprl *IPRules) Whitelist(ip string) error {
	checkValidIP(ip)

	if err := iprl.WhitelistedIPs.AddString(ip); err != nil {
		return err
	}

	return nil
}

func (iprl *IPRules) Blacklist(ip string) error {
	checkValidIP(ip)

	if err := iprl.BlacklistedIPs.AddString(ip); err != nil {
		return err
	}

	return nil
}

// Checks
func checkValidIP(ipstr string) {
	if !isValidIPString(ipstr) {
		fmt.Println(fmt.Sprintf("[%s] is not a valid IP address", ipstr))
		os.Exit(1)
	}
}

func checkValidIPRange(lower net.IP, upper net.IP) {
	if !isValidIPRange(lower, upper) {
		fmt.Println(fmt.Sprintf("[%s-%s] is not a valid host range", lower.String(), upper.String()))
		os.Exit(1)
	}
}

func isValidIPString(ipstr string) bool {
	if val := net.ParseIP(ipstr); val == nil {
		return false
	}

	return true
}

func isValidIPRange(lower net.IP, upper net.IP) bool {
	if bytes.Compare(lower, upper) > 0 {
		return false
	}

	return true
}
