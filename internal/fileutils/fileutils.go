package fileutils

import (
	"os"
)

// Exists check if a given file exists
func Exists(filepath string) (bool, error) {
	var err error
	ok := true

	if f, openError := os.Open(filepath); openError != nil {
		_ = f.Close()
		// Return an error only if it is not a "not exist" error
		if os.IsNotExist(openError) {
			ok = false
		} else {
			err = openError
		}

	}

	return ok, err
}
