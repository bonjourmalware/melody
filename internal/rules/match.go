package rules

import (
	"github.com/bonjourmalware/pinknoise/internal/events"
)

func (rule *Rule) MatchICMPv4Event(ev events.ICMPv4Event) bool {
	var condOK bool

	//if rule.ID != nil {
	//	if ev.IPHeader.Id != *rule.ID {
	//		return false
	//	}
	//}
	// The rule fails if the source IP is blacklisted
	if len(rule.IPs.BlacklistedIPs) > 0 {
		for _, iprange := range rule.IPs.BlacklistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				return false
			}
		}
	}

	// The rule fails if the source IP is not in the whitelisted addresses
	if len(rule.IPs.WhitelistedIPs) > 0 {
		condOK = false

		for _, iprange := range rule.IPs.WhitelistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				condOK = true
				break
			}
		}

		if !condOK {
			return false
		}
	}

	if rule.Options.MatchAll {
		if rule.TTL != nil {
			if ev.IPHeader.TTL != *rule.TTL {
				return false
			}
		}

		if rule.TOS != nil {
			if ev.IPHeader.TOS != *rule.TOS {
				return false
			}
		}

		return true
	}

	if rule.TTL != nil {
		if ev.IPHeader.TTL == *rule.TTL {
			return true
		}
	}

	if rule.TOS != nil {
		if ev.IPHeader.TOS == *rule.TOS {
			return true
		}
	}

	return false
}

func (rule *Rule) MatchTCPEvent(ev events.TCPEvent) bool {
	var condOK bool

	if len(rule.Ports) > 0 {
		for _, port := range rule.Ports {
			// If at least one port is valid
			if port == ev.DestPort {
				break
			}
		}
	}

	// The rule fails if the source IP is blacklisted
	if len(rule.IPs.BlacklistedIPs) > 0 {
		for _, iprange := range rule.IPs.BlacklistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				return false
			}
		}
	}

	// The rule fails if the source IP is not in the whitelisted addresses
	if len(rule.IPs.WhitelistedIPs) > 0 {
		condOK = false

		for _, iprange := range rule.IPs.WhitelistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				condOK = true
				break
			}
		}

		if !condOK {
			return false
		}
	}

	if rule.Options.MatchAll {
		if len(rule.Flags) > 0 {
			condOK = false
			for _, flags := range rule.Flags {
				// If at least one of the flag string match exactly, then continue
				if ev.TCPHeader.BaseLayer.Contents[13]^(*flags) == 0 {
					condOK = true
					break
				}
			}
			if !condOK {
				return false
			}
		}

		if rule.Seq != nil {
			if ev.TCPHeader.Seq != *rule.Seq {
				return false
			}
		}

		if rule.Ack != nil {
			if ev.TCPHeader.Ack != *rule.Ack {
				return false
			}
		}

		if rule.Window != nil {
			if ev.TCPHeader.Window != *rule.Window {
				return false
			}
		}

		if rule.Payload != nil {
			if rule.Payload.Match(ev.TCPHeader.Payload, rule.Options) == false {
				return false
			}
		}

		//TODO : Add <, > and <> operators
		if rule.Dsize != nil {
			if len(ev.TCPHeader.Payload) != *rule.Dsize {
				return false
			}
		}

		if len(rule.Fragbits) > 0 {
			condOK = false
			for _, fragbits := range rule.Fragbits {
				// If at least one of the flag string match exactly, then continue
				if uint8(ev.IPHeader.Flags)^(*fragbits) == 0 {
					condOK = true
					break
				}
			}
			if !condOK {
				return false
			}
		}

		if rule.TTL != nil {
			if ev.IPHeader.TTL != *rule.TTL {
				return false
			}
		}

		if rule.TOS != nil {
			if ev.IPHeader.TOS != *rule.TOS {
				return false
			}
		}

		//if rule.ID != nil {
		//	if ev.IPHeader.Id != *rule.ID {
		//		return false
		//	}
		//}

		return true
	}

	// else
	if len(rule.Flags) > 0 {
		for _, flags := range rule.Flags {
			// If at least one of the flag string match exactly, then continue
			if ev.TCPHeader.BaseLayer.Contents[13]^(*flags) == 0 {
				return true
			}
		}
	}

	if rule.Seq != nil {
		if ev.TCPHeader.Seq == *rule.Seq {
			return true
		}
	}

	if rule.Ack != nil {
		if ev.TCPHeader.Ack == *rule.Ack {
			return true
		}
	}

	if rule.Window != nil {
		if ev.TCPHeader.Window == *rule.Window {
			return true
		}
	}

	if rule.Payload != nil {
		if rule.Payload.Match(ev.TCPHeader.Payload, rule.Options) == true {
			return true
		}
	}

	//TODO : Add <, > and <> operators
	if rule.Dsize != nil {
		if len(ev.TCPHeader.Payload) == *rule.Dsize {
			return true
		}
	}

	if len(rule.Fragbits) > 0 {
		for _, fragbits := range rule.Fragbits {
			// If at least one of the flag string match exactly, then continue
			if uint8(ev.IPHeader.Flags)^(*fragbits) == 0 {
				return true
			}
		}
	}

	if rule.TTL != nil {
		if ev.IPHeader.TTL == *rule.TTL {
			return true
		}
	}

	if rule.TOS != nil {
		if ev.IPHeader.TOS == *rule.TOS {
			return true
		}
	}

	//if rule.ID != nil {
	//	if ev.IPHeader.Id != *rule.ID {
	//		return false
	//	}
	//}

	return false
}

func (rule *Rule) MatchHTTPEvent(ev events.HTTPEvent) bool {
	var condOK bool

	if len(rule.Ports) > 0 {
		var portMatch bool
		for _, port := range rule.Ports {
			// If at least one port is valid
			if port == ev.DestPort {
				portMatch = true
				break
			}
		}

		if portMatch == false {
			return false
		}
	}

	// The rule fails if the source IP is blacklisted
	if len(rule.IPs.BlacklistedIPs) > 0 {
		for _, iprange := range rule.IPs.BlacklistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				return false
			}
		}
	}

	// The rule fails if the source IP is not in the whitelisted addresses
	if len(rule.IPs.WhitelistedIPs) > 0 {
		condOK = false

		for _, iprange := range rule.IPs.WhitelistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				condOK = true
				break
			}
		}

		if !condOK {
			return false
		}
	}

	if rule.Options.MatchAll {
		if rule.URI != nil {
			if rule.URI.Match([]byte(ev.RequestURI), rule.Options) == false {
				return false
			}
		}

		if rule.Body != nil {
			if rule.Body.Match([]byte(ev.Body.Content), rule.Options) == false {
				return false
			}
		}

		if rule.Headers != nil {
			condOK = false

			for _, inlineHeader := range ev.InlineHeaders {
				if rule.Headers.Match([]byte(inlineHeader), rule.Options) == true {
					condOK = true
					break
				}
			}

			if !condOK {
				return false
			}
		}

		if rule.Verb != nil {
			if rule.Verb.Match([]byte(ev.Verb), rule.Options) == false {
				return false
			}
		}

		if rule.Proto != nil {
			if rule.Proto.Match([]byte(ev.Proto), rule.Options) == false {
				return false
			}
		}
	}

	// else

	if rule.URI != nil {
		if rule.URI.Match([]byte(ev.RequestURI), rule.Options) == true {
			return true
		}
	}

	if rule.Body != nil {
		if rule.Body.Match([]byte(ev.Body.Content), rule.Options) == true {
			return true
		}
	}

	if rule.Headers != nil {
		condOK = false

		for _, inlineHeader := range ev.InlineHeaders {
			if rule.Headers.Match([]byte(inlineHeader), rule.Options) == true {
				condOK = true
				break
			}
		}

		if !condOK {
			return false
		}
	}

	if rule.Verb != nil {
		if rule.Verb.Match([]byte(ev.Verb), rule.Options) == true {
			return true
		}
	}

	if rule.Proto != nil {
		if rule.Proto.Match([]byte(ev.Proto), rule.Options) == true {
			return true
		}
	}

	return true
}
