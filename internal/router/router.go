package router

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/bonjourmalware/pinknoise/internal/events"

	"github.com/bonjourmalware/pinknoise/internal/logging"

	"github.com/bonjourmalware/pinknoise/internal/config"
)

func StartHTTP(quitErrChan chan error) {
	r := http.NewServeMux()
	r.Handle("/",
		headersHandler(
			melodyFs(http.Dir(config.Cfg.ServerHTTPDir), config.Cfg.ServerHTTPMissingResponseStatus),
			config.Cfg.ServerHTTPHeaders))

	logging.Std.Println("Started HTTP server on port", config.Cfg.ServerHTTPPort)
	time.Sleep(1 * time.Second)
	quitErrChan <- http.ListenAndServe(fmt.Sprintf(":%d", config.Cfg.ServerHTTPPort), r)
}

func StartHTTPS(quitErrChan chan error, eventChan chan events.Event) {
	r := http.NewServeMux()
	r.Handle("/",
		httpsLogger(
			headersHandler(
				melodyFs(http.Dir(config.Cfg.ServerHTTPSDir), config.Cfg.ServerHTTPSMissingResponseStatus),
				config.Cfg.ServerHTTPSHeaders), eventChan))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Cfg.ServerHTTPSPort),
		Handler:      r,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	logging.Std.Println("Started HTTPS server on port", config.Cfg.ServerHTTPSPort)
	time.Sleep(1 * time.Second)
	quitErrChan <- srv.ListenAndServeTLS(config.Cfg.ServerHTTPSCert, config.Cfg.ServerHTTPSKey)
}
