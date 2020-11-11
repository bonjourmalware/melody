package logdata

import (
	"encoding/json"

	"github.com/google/gopacket/layers"
)

type ICMPv6LogData struct {
	TypeCode     layers.ICMPv6TypeCode `json:"type_code"`
	Type         uint8                 `json:"type"`
	Code         uint8                 `json:"code"`
	TypeCodeName string                `json:"type_code_name"`
	Checksum     uint16                `json:"checksum"`
}

type ICMPv6EventLog struct {
	ICMPv6 ICMPv6LogData `json:"icmpv6"`
	IP     IPv6LogData   `json:"ip"`
	BaseLogData
}

func (eventLog ICMPv6EventLog) String() (string, error) {
	data, err := json.Marshal(eventLog)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

