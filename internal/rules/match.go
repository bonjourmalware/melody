package rules

import (
	"github.com/bonjourmalware/pinknoise/internal/config"
	"github.com/bonjourmalware/pinknoise/internal/events"
)

func (rule *Rule) Match(ev events.Event) bool {
	var condOK bool
	//ipHeader := ev.GetIPv4Header()

	// The rule fails if the source IP is blacklisted
	if len(rule.IPs.BlacklistedIPs) > 0 {
		for _, iprange := range rule.IPs.BlacklistedIPs {
			if iprange.ContainsIPString(ev.GetSourceIP()) {
				return false
			}
		}
	}

	// The rule fails if the source IP is not in the whitelisted addresses
	if len(rule.IPs.WhitelistedIPs) > 0 {
		condOK = false

		for _, iprange := range rule.IPs.WhitelistedIPs {
			if iprange.ContainsIPString(ev.GetSourceIP()) {
				condOK = true
				break
			}
		}

		if !condOK {
			return false
		}
	}

	switch ev.GetKind() {
	case config.UDPKind:
		return rule.MatchUDPEvent(ev)
	case config.TCPKind:
		return rule.MatchTCPEvent(ev)
	case config.ICMPv4Kind:
		return rule.MatchICMPv4Event(ev)
	case config.ICMPv6Kind:
		return rule.MatchICMPv6Event(ev)
	case config.HTTPKind:
		return rule.MatchHTTPEvent(ev)
	}

	return false
}

func (rule *Rule) MatchICMPv6Event(ev events.Event) bool {
	icmpv6Header := ev.GetICMPv6Header()

	if rule.MatchAll {
		if rule.ICMPv6.Checksum != nil {
			if icmpv6Header.Checksum != *rule.ICMPv6.Checksum {
				return false
			}
		}

		if rule.ICMPv6.TypeCode != nil {
			if uint16(icmpv6Header.TypeCode) != *rule.ICMPv6.TypeCode {
				return false
			}
		}

		if rule.ICMPv6.Code != nil {
			if icmpv6Header.TypeCode.Code() != *rule.ICMPv6.Code {
				return false
			}
		}

		if rule.ICMPv6.Type != nil {
			if icmpv6Header.TypeCode.Type() != *rule.ICMPv6.Type {
				return false
			}
		}

		return true
	}

	if rule.ICMPv6.Checksum != nil {
		if icmpv6Header.Checksum == *rule.ICMPv6.Checksum {
			return true
		}
	}

	if rule.ICMPv6.TypeCode != nil {
		if uint16(icmpv6Header.TypeCode) == *rule.ICMPv6.TypeCode {
			return true
		}
	}

	if rule.ICMPv6.Code != nil {
		if icmpv6Header.TypeCode.Code() == *rule.ICMPv6.Code {
			return true
		}
	}

	if rule.ICMPv6.Type != nil {
		if icmpv6Header.TypeCode.Type() == *rule.ICMPv6.Type {
			return true
		}
	}

	return false
}

func (rule *Rule) MatchICMPv4Event(ev events.Event) bool {
	icmpv4Header := ev.GetICMPv4Header()

	if rule.MatchAll {
		if rule.ICMPv4.Checksum != nil {
			if icmpv4Header.Checksum != *rule.ICMPv4.Checksum {
				return false
			}
		}

		if rule.ICMPv4.Seq != nil {
			if icmpv4Header.Seq != *rule.ICMPv4.Seq {
				return false
			}
		}

		if rule.ICMPv4.TypeCode != nil {
			if uint16(icmpv4Header.TypeCode) != *rule.ICMPv4.TypeCode {
				return false
			}
		}

		if rule.ICMPv4.Code != nil {
			if icmpv4Header.TypeCode.Code() != *rule.ICMPv4.Code {
				return false
			}
		}

		if rule.ICMPv4.Type != nil {
			if icmpv4Header.TypeCode.Type() != *rule.ICMPv4.Type {
				return false
			}
		}

		return true
	}

	if rule.ICMPv4.Checksum != nil {
		if icmpv4Header.Checksum == *rule.ICMPv4.Checksum {
			return true
		}
	}

	if rule.ICMPv4.TypeCode != nil {
		if uint16(icmpv4Header.TypeCode) == *rule.ICMPv4.TypeCode {
			return true
		}
	}

	if rule.ICMPv4.Code != nil {
		if icmpv4Header.TypeCode.Code() == *rule.ICMPv4.Code {
			return true
		}
	}

	if rule.ICMPv4.Type != nil {
		if icmpv4Header.TypeCode.Type() == *rule.ICMPv4.Type {
			return true
		}
	}

	if rule.ICMPv4.Seq != nil {
		if icmpv4Header.Seq == *rule.ICMPv4.Seq {
			return true
		}
	}

	return false
}

func (rule *Rule) MatchUDPEvent(ev events.Event) bool {
	udpHeader := ev.GetUDPHeader()

	if rule.MatchAll {
		if len(rule.Ports) > 0 {
			var condOK = false

			for _, port := range rule.Ports {
				// If at least one port is valid
				if port == uint16(udpHeader.DstPort) {
					condOK = true
					break
				}
			}

			if !condOK {
				return false
			}
		}

		//TODO : Add <, > and <> operators
		if rule.UDP.Length != nil {
			if udpHeader.Length != *rule.UDP.Length {
				return false
			}
		}

		if rule.UDP.Checksum != nil {
			if udpHeader.Checksum != *rule.UDP.Checksum {
				return false
			}
		}

		if rule.UDP.Payload != nil {
			if !rule.UDP.Payload.Match(udpHeader.Payload) {
				return false
			}
		}

		//TODO : Add <, > and <> operators
		if rule.UDP.Dsize != nil {
			if uint(len(udpHeader.Payload)) != *rule.UDP.Dsize {
				return false
			}
		}

		return true
	}

	if len(rule.Ports) > 0 {
		for _, port := range rule.Ports {
			// If at least one port is valid
			if port == uint16(udpHeader.DstPort) {
				return true
			}
		}
	}

	//TODO : Add <, > and <> operators
	if rule.UDP.Length != nil {
		if udpHeader.Length == *rule.UDP.Length {
			return true
		}
	}

	if rule.UDP.Checksum != nil {
		if udpHeader.Checksum == *rule.UDP.Checksum {
			return true
		}
	}

	if rule.UDP.Payload != nil {
		if rule.UDP.Payload.Match(udpHeader.Payload) {
			return true
		}
	}

	//TODO : Add <, > and <> operators
	if rule.UDP.Dsize != nil {
		if uint(len(udpHeader.Payload)) == *rule.UDP.Dsize {
			return true
		}
	}

	return false
}

func (rule *Rule) MatchTCPEvent(ev events.Event) bool {
	tcpHeader := ev.GetTCPHeader()

	var condOK bool

	if rule.MatchAll {
		if len(rule.Ports) > 0 {
			var condOK = false

			for _, port := range rule.Ports {
				// If at least one port is valid
				if port == uint16(tcpHeader.DstPort) {
					condOK = true
					break
				}
			}

			if !condOK {
				return false
			}
		}

		if len(rule.TCP.Flags) > 0 {
			condOK = false
			for _, flags := range rule.TCP.Flags {
				// If at least one of the flag string match exactly, then continue
				if tcpHeader.BaseLayer.Contents[13]^(*flags) == 0 {
					condOK = true
					break
				}
			}
			if !condOK {
				return false
			}
		}

		if rule.TCP.Seq != nil {
			if tcpHeader.Seq != *rule.TCP.Seq {
				return false
			}
		}

		if rule.TCP.Ack != nil {
			if tcpHeader.Ack != *rule.TCP.Ack {
				return false
			}
		}

		if rule.TCP.Window != nil {
			if tcpHeader.Window != *rule.TCP.Window {
				return false
			}
		}

		if rule.TCP.Payload != nil {
			if !rule.TCP.Payload.Match(tcpHeader.Payload) {
				return false
			}
		}

		//TODO : Add <, > and <> operators
		if rule.TCP.Dsize != nil {
			if uint(len(tcpHeader.Payload)) != *rule.TCP.Dsize {
				return false
			}
		}

		return true
	}

	// else
	if len(rule.Ports) > 0 {
		for _, port := range rule.Ports {
			// If at least one port is valid
			if port == uint16(tcpHeader.DstPort) {
				return true
			}
		}
	}

	if len(rule.TCP.Flags) > 0 {
		for _, flags := range rule.TCP.Flags {
			// If at least one of the flag string match exactly, then continue
			if tcpHeader.BaseLayer.Contents[13]^(*flags) == 0 {
				return true
			}
		}
	}

	if rule.TCP.Seq != nil {
		if tcpHeader.Seq == *rule.TCP.Seq {
			return true
		}
	}

	if rule.TCP.Ack != nil {
		if tcpHeader.Ack == *rule.TCP.Ack {
			return true
		}
	}

	if rule.TCP.Window != nil {
		if tcpHeader.Window == *rule.TCP.Window {
			return true
		}
	}

	if rule.TCP.Payload != nil {
		if rule.TCP.Payload.Match(tcpHeader.Payload) {
			return true
		}
	}

	//TODO : Add <, > and <> operators
	if rule.TCP.Dsize != nil {
		if uint(len(tcpHeader.Payload)) == *rule.TCP.Dsize {
			return true
		}
	}

	return false
}

func (rule *Rule) MatchHTTPEvent(ev events.Event) bool {
	httpData := ev.GetHTTPData()

	var condOK bool

	if rule.MatchAll {
		if len(rule.Ports) > 0 {
			var condOK = false

			for _, port := range rule.Ports {
				// If at least one port is valid
				if port == httpData.DestPort {
					condOK = true
					break
				}
			}

			if !condOK {
				return false
			}
		}

		if rule.HTTP.URI != nil {
			if rule.HTTP.URI.Match([]byte(httpData.RequestURI)) == false {
				return false
			}
		}

		if rule.HTTP.Body != nil {
			if rule.HTTP.Body.Match([]byte(httpData.Body.Content)) == false {
				return false
			}
		}

		if rule.HTTP.Headers != nil {
			condOK = false

			for _, inlineHeader := range httpData.InlineHeaders {
				if rule.HTTP.Headers.Match([]byte(inlineHeader)) == true {
					condOK = true
					break
				}
			}

			if !condOK {
				return false
			}
		}

		if rule.HTTP.Verb != nil {
			if rule.HTTP.Verb.Match([]byte(httpData.Verb)) == false {
				return false
			}
		}

		if rule.HTTP.Proto != nil {
			if rule.HTTP.Proto.Match([]byte(httpData.Proto)) == false {
				return false
			}
		}

		if rule.HTTP.TLS != nil {
			if *rule.HTTP.TLS != httpData.IsTLS {
				return false
			}
		}
	}

	if len(rule.Ports) > 0 {
		for _, port := range rule.Ports {
			// If at least one port is valid
			if port == httpData.DestPort {
				return true
			}
		}
	}

	if rule.HTTP.URI != nil {
		if rule.HTTP.URI.Match([]byte(httpData.RequestURI)) == true {
			return true
		}
	}

	if rule.HTTP.Body != nil {
		if rule.HTTP.Body.Match([]byte(httpData.Body.Content)) == true {
			return true
		}
	}

	if rule.HTTP.Headers != nil {
		condOK = false

		for _, inlineHeader := range httpData.InlineHeaders {
			if rule.HTTP.Headers.Match([]byte(inlineHeader)) == true {
				condOK = true
				break
			}
		}

		if condOK {
			return true
		}
	}

	if rule.HTTP.Verb != nil {
		if rule.HTTP.Verb.Match([]byte(httpData.Verb)) == true {
			return true
		}
	}

	if rule.HTTP.Proto != nil {
		if rule.HTTP.Proto.Match([]byte(httpData.Proto)) == true {
			return true
		}
	}

	if rule.HTTP.TLS != nil {
		if *rule.HTTP.TLS == httpData.IsTLS {
			return true
		}
	}

	return false
}
