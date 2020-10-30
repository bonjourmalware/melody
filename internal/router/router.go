package router

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/bonjourmalware/pinknoise/internal/events"

	"github.com/bonjourmalware/pinknoise/internal/logger"

	"github.com/bonjourmalware/pinknoise/internal/config"
)

//func StartHTTP(quitErrChan chan error) {
//	fs := http.FileServer(http.Dir(config.Cfg.ServerHTTPDir))
//	http.Handle("/", fs)
//
//	fmt.Println("Started HTTP server on port :", config.Cfg.ServerHTTPPort)
//	quitErrChan <- http.ListenAndServe(fmt.Sprintf(":%d", config.Cfg.ServerHTTPPort), nil)
//}

func StartHTTP(quitErrChan chan error) {
	r := http.NewServeMux()
	r.Handle("/",
		headersHandler(
			http.FileServer(
				neuteredFileSystem{
					http.Dir(config.Cfg.ServerHTTPDir),
				}), config.Cfg.ServerHTTPHeaders))

	logger.Std.Println("Started HTTP server on port :", config.Cfg.ServerHTTPPort)
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

	logger.Std.Println("Started HTTPS server on port :", config.Cfg.ServerHTTPSPort)
	quitErrChan <- srv.ListenAndServeTLS(config.Cfg.ServerHTTPSCert, config.Cfg.ServerHTTPSKey)
}

//func StartHTTPS(quitErrChan chan error) {
//	fs := http.FileServer(http.Dir(config.Cfg.ServerHTTPSDir))
//	http.Handle("/", fs)
//
//	fmt.Println("Started HTTPS server on port :", config.Cfg.ServerHTTPSPort)
//	quitErrChan <- http.ListenAndServeTLS(fmt.Sprintf(":%d", config.Cfg.ServerHTTPSPort), "server.crt", "server.key", nil)
//}
//
//func StartHTTPS(port int, quitErrChan chan error, eventChan chan Event) {
//	HTTPSRouter := http.NewServeMux()
//	handler := http.HandlerFunc(IndexHTTPS)
//	HTTPSRouter.Handle("/", handler)
//
//	srv := &http.Server{
//		Addr:         fmt.Sprintf(":%d", config.Cfg.ServerHTTPSPort),
//		Handler:      HTTPSRouter,
//		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
//	}
//
//	fmt.Println("Started HTTPS server on port :", config.Cfg.ServerHTTPSPort)
//	quitErrChan <- srv.ListenAndServeTLS("server.crt", "server.key")
//}
