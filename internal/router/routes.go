package router

import (
	"github.com/bonjourmalware/melody/internal/config"
	"net/http"
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
