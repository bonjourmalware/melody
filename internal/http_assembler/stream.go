package http_assembler

import (
	"bufio"
	"github.com/bonjourmalware/pinknoise/internal/engine"
	"github.com/bonjourmalware/pinknoise/internal/events"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"net/http"
)

// HttpStreamFactory implements tcpassembly.StreamFactory
type HttpStreamFactory struct{}

// HttpStream will handle the actual decoding of http requests.
type HttpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *HttpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &HttpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *HttpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
		} else {
			ev, _ := events.NewHTTPEvent(req, h.net, h.transport)
			engine.EventChan <- ev
		}
	}
}
