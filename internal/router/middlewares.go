package router

import (
	"log"
	"net/http"
	"path/filepath"

	"github.com/bonjourmalware/pinknoise/internal/events"
)

// https://www.alexedwards.net/blog/disable-http-fileserver-directory-listings#using-a-custom-filesystem
type neuteredFileSystem struct {
	fs http.FileSystem
}

func (nfs neuteredFileSystem) Open(path string) (http.File, error) {
	f, err := nfs.fs.Open(path)
	if err != nil {
		return nil, err
	}

	s, _ := f.Stat()
	if s.IsDir() {
		index := filepath.Join(path, "index.html")
		if _, err := nfs.fs.Open(index); err != nil {
			closeErr := f.Close()
			if closeErr != nil {
				return nil, closeErr
			}

			return nil, err
		}
	}

	return f, nil
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
		} else {
			eventChan <- ev
		}

		h.ServeHTTP(w, r) // pass request
	})
}
