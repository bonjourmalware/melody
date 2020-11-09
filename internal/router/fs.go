package router

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// https://www.alexedwards.net/blog/disable-http-fileserver-directory-listings#using-a-custom-filesystem
type neuteredFileSystem struct {
	fs http.FileSystem
}

func melodyFs(root http.FileSystem, notFoundCode int) http.Handler {
	fs := http.FileServer(
		neuteredFileSystem{
			root,
		})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//make sure the url path starts with /
		upath := r.URL.Path
		if !strings.HasPrefix(upath, "/") {
			upath = "/" + upath
			r.URL.Path = upath
		}
		upath = path.Clean(upath)

		// attempt to open the file via the http.FileSystem
		f, err := root.Open(upath)
		if err != nil {
			if os.IsNotExist(err) {
				w.WriteHeader(notFoundCode)
				_, _ = w.Write([]byte{})
				return
			}
		}

		s, _ := f.Stat()
		if s.IsDir() {
			index := filepath.Join(upath, "index.html")
			if _, err := root.Open(index); err != nil {
				_ = f.Close()
				if os.IsNotExist(err) {
					w.WriteHeader(notFoundCode)
					_, _ = w.Write([]byte{})
					return
				}
			}
		}

		fs.ServeHTTP(w, r)
	})
}
