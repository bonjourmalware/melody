package logdata

import (
	"encoding/json"

	"github.com/google/gopacket/layers"
)

// ICMPv4LogData is the struct describing the logged data for ICMPv4 packets
type ICMPv4LogData struct {
	TypeCode     layers.ICMPv4TypeCode `json:"type_code"`
	Type         uint8                 `json:"type"`
	Code         uint8                 `json:"code"`
	TypeCodeName string                `json:"type_code_name"`
	Checksum     uint16                `json:"checksum"`
	ID           uint16                `json:"id"`
	Seq          uint16                `json:"seq"`
}

// ICMPv4EventLog is the event log struct for ICMPv4 packets
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
