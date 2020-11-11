package logdata

import (
	"encoding/json"

	"github.com/google/gopacket/layers"
)

type ICMPv4LogData struct {
	TypeCode     layers.ICMPv4TypeCode `json:"type_code"`
	Type         uint8                 `json:"type"`
	Code         uint8                 `json:"code"`
	TypeCodeName string                `json:"type_code_name"`
	Checksum     uint16                `json:"checksum"`
	Id           uint16                `json:"id"`
	Seq          uint16                `json:"seq"`
}

type ICMPv4EventLog struct {
	ICMPv4 ICMPv4LogData `json:"icmpv4"`
	IP     IPv4LogData   `json:"ip"`
	BaseLogData
}

func (eventLog ICMPv4EventLog) String() (string, error) {
	data, err := json.Marshal(eventLog)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
