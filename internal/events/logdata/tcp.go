package logdata

import (
	"encoding/json"
)

type TCPLogData struct {
	Window     uint16  `json:"window"`
	Seq        uint32  `json:"seq"`
	Ack        uint32  `json:"ack"`
	DataOffset uint8   `json:"data_offset"`
	Flags      string  `json:"flags"`
	Urgent     uint16  `json:"urgent"`
	Payload    Payload `json:"payload"`
}

type TCPEventLog struct {
	TCP TCPLogData `json:"tcp"`
	IP  IPLogData  `json:"ip"`
	BaseLogData
}

func (eventLog TCPEventLog) String() (string, error) {
	data, err := json.Marshal(eventLog)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
