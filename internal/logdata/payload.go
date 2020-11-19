package logdata

import "encoding/base64"

// Payload is the struct describing the logged data packets' payload when supported
type Payload struct {
	Content   string `json:"content"`
	Base64    string `json:"base64"`
	Truncated bool   `json:"truncated"`
}

// NewPayloadLogData is used to create a new Payload struct
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
