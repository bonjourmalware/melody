package logdata

import "encoding/json"

// UDPLogData is the struct describing the logged data for UDP packets
type UDPLogData struct {
	Payload  Payload `json:"payload"`
	Length   uint16  `json:"length"`
	Checksum uint16  `json:"checksum"`
}

// UDPEventLog is the event log struct for UDP packets
type UDPEventLog struct {
	UDP UDPLogData `json:"udp"`
	IP  IPLogData  `json:"ip"`
	BaseLogData
}

func (eventLog UDPEventLog) String() (string, error) {
	data, err := json.Marshal(eventLog)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
