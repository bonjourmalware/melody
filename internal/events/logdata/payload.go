package logdata

import "encoding/base64"

type Payload struct {
	Content   string `json:"content"`
	Base64    string `json:"base64"`
	Truncated bool   `json:"truncated"`
}

func NewPayloadLogData(data []byte, maxLength uint64) Payload {
	var pl = Payload{}

	if uint64(len(data)) > maxLength {
		data = data[:maxLength]
		pl.Truncated = true
	}
	pl.Content = string(data)
	pl.Base64 = base64.StdEncoding.EncodeToString(data)
	return pl
}
