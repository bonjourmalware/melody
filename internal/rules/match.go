package rules

import (
	"bytes"

	"gitlab.com/Alvoras/pinknoise/internal/events"
)

func (r *Rule) MatchICMPv4Event(ev events.ICMPv4Event) bool {
	if r.TTL != nil {
		if ev.IPHeader.TTL != *r.TTL {
			return false
		}
	}

	if r.TOS != nil {
		if ev.IPHeader.TOS != *r.TOS {
			return false
		}
	}

	if r.ID != nil {
		if ev.IPHeader.Id != *r.ID {
			return false
		}
	}
	// The rule fails if the source IP is blacklisted
	if len(r.IPs.BlacklistedIPs) > 0 {
		for _, iprange := range r.IPs.BlacklistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				return false
			}
		}
	}

	// The rule fails if the source IP is not in the whitelisted addresses
	if len(r.IPs.WhitelistedIPs) > 0 {
		var match = false

		for _, iprange := range r.IPs.WhitelistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				match = true
				break
			}
		}

		if !match {
			return false
		}
	}

	return true
}

func (r *Rule) MatchTCPEvent(ev events.TCPEvent) bool {
	if len(r.Ports) > 0 {
		for _, port := range r.Ports {
			// If at least one port is valid
			if port == ev.DestPort {
				break
			}
		}
	}

	// The rule fails if the source IP is blacklisted
	if len(r.IPs.BlacklistedIPs) > 0 {
		for _, iprange := range r.IPs.BlacklistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				return false
			}
		}
	}

	// The rule fails if the source IP is not in the whitelisted addresses
	if len(r.IPs.WhitelistedIPs) > 0 {
		var match = false

		for _, iprange := range r.IPs.WhitelistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				match = true
				break
			}
		}

		if !match {
			return false
		}
	}

	//TODO add support for "Not" option
	if r.Flags != nil && ev.TCPHeader.BaseLayer.Contents[13]^(*r.Flags) != 0 {
		return false
	}

	if r.Seq != nil {
		if ev.TCPHeader.Seq != *r.Seq {
			return false
		}
	}

	if r.Ack != nil {
		if ev.TCPHeader.Ack != *r.Ack {
			return false
		}
	}

	if r.Window != nil {
		if ev.TCPHeader.Window != *r.Window {
			return false
		}
	}

	if len(r.Payload.Values) > 0 {
		if r.Payload.Match(ev.TCPHeader.Payload, *r) == false {
			return false
		}
	}

	//TODO : Add <, > and <> operators
	if r.Dsize != nil {
		if len(ev.TCPHeader.Payload) != *r.Dsize {
			return false
		}
	}

	//TODO add support for "Not" option
	if r.Fragbits != nil && uint8(ev.IPHeader.Flags)^(*r.Fragbits) != 0 {
		return false
	}

	if r.TTL != nil {
		if ev.IPHeader.TTL != *r.TTL {
			return false
		}
	}

	if r.TOS != nil {
		if ev.IPHeader.TOS != *r.TOS {
			return false
		}
	}

	if r.ID != nil {
		if ev.IPHeader.Id != *r.ID {
			return false
		}
	}


	return true
}

func (r Rule) MatchBytesWithOffsetAndDepth(received []byte, ruleValue ReversableValue, ruleOptions Options) bool {
	var match bool
	var ruleValueContent = ruleValue.ByteValue

	if ruleValue.Nocase || ruleOptions.Nocase {
		received = bytes.ToLower(received)
	}

	if r.Offset > 0 {
		received = received[r.Offset:]
	}

	if r.Depth > 0 {
		received = received[:r.Depth]
	}

	if ruleValue.Exact || ruleOptions.Exact {
		if bytes.Compare(received, ruleValueContent) == 0 {
			match = true
		}
	} else {
		if ruleValue.CompiledRegex != nil {
			match = ruleValue.CompiledRegex.Match(received)
		} else if bytes.Contains(received, ruleValueContent) {
			match = true
		}
	}
	return match
}

func (r *Rule) MatchHTTPEvent(ev events.HTTPEvent) bool {
	if len(r.Ports) > 0 {
		var portMatch bool
		for _, port := range r.Ports {
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
	if len(r.IPs.BlacklistedIPs) > 0 {
		for _, iprange := range r.IPs.BlacklistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				return false
			}
		}
	}

	// The rule fails if the source IP is not in the whitelisted addresses
	if len(r.IPs.WhitelistedIPs) > 0 {
		var match = false

		for _, iprange := range r.IPs.WhitelistedIPs {
			if iprange.ContainsIPString(ev.SourceIP) {
				match = true
				break
			}
		}

		if !match {
			return false
		}
	}

	if len(r.URI.Values) > 0 {
		if r.URI.Match([]byte(ev.RequestURI), *r) == false {
			return false
		}
	}

	if len(r.Body.Values) > 0 {
		if r.Body.Match([]byte(ev.Body.Content), *r) == false {
			return false
		}
	}

	if len(r.Headers.Values) > 0 {
		var match = false

		for _, header := range ev.InlineHeaders {
			if r.Headers.Match([]byte(header), *r) {
				match = true
				break
			}
		}

		if !match {
			return false
		}
	}
	if len(r.Verb.Values) > 0 {
		if r.Verb.Match([]byte(ev.Verb), *r) == false {
			return false
		}
	}

	if len(r.Proto.Values) > 0 {
		if r.Proto.Match([]byte(ev.Proto), *r) == false {
			return false
		}
	}

	return true
}
