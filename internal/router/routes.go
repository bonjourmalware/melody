package router

import (
	"github.com/bonjourmalware/pinknoise/internal/events"
	"log"
	"net/http"

	"github.com/bonjourmalware/pinknoise/internal/config"
)

func Index(w http.ResponseWriter, _ *http.Request) {
	for header, val := range config.Cfg.ServerHTTPHeaders {
		w.Header().Set(header, val)
	}
}

func IndexHTTPS(w http.ResponseWriter, _ *http.Request) {
	for header, val := range config.Cfg.ServerHTTPSHeaders {
		w.Header().Set(header, val)
	}
}

func headersHandler(h http.Handler, headers map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for header, val := range headers {
			w.Header().Set(header, val)
		}
		h.ServeHTTP(w, r) // pass request
	})
}

func httpsLogger(h http.Handler, eventChan chan events.Event) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ev, err := events.NewHTTPEventFromRequest(r)
		if err != nil {
			//TODO: write to error log
			log.Println("ERROR", err)
			return
		}else{
			eventChan <- ev
		}

		h.ServeHTTP(w, r) // pass request
	})
}
