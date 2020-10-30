package router

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/bonjourmalware/pinknoise/internal/events"

	"github.com/bonjourmalware/pinknoise/internal/logging"

	"github.com/bonjourmalware/pinknoise/internal/config"
)

func StartHTTP(quitErrChan chan error) {
	r := http.NewServeMux()
	r.Handle("/",
		headersHandler(
			http.FileServer(
				neuteredFileSystem{
					http.Dir(config.Cfg.ServerHTTPDir),
				}), config.Cfg.ServerHTTPHeaders))

	logging.Std.Println("Started HTTP server on port :", config.Cfg.ServerHTTPPort)
	quitErrChan <- http.ListenAndServe(fmt.Sprintf(":%d", config.Cfg.ServerHTTPPort), r)
}

func StartHTTPS(quitErrChan chan error, eventChan chan events.Event) {
	r := http.NewServeMux()
	r.Handle("/",
		httpsLogger(
			headersHandler(
				http.FileServer(
					neuteredFileSystem{
						http.Dir(config.Cfg.ServerHTTPSDir),
					}),
				config.Cfg.ServerHTTPSHeaders), eventChan))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Cfg.ServerHTTPSPort),
		Handler:      r,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	logging.Std.Println("Started HTTPS server on port :", config.Cfg.ServerHTTPSPort)
	quitErrChan <- srv.ListenAndServeTLS(config.Cfg.ServerHTTPSCert, config.Cfg.ServerHTTPSKey)
}
