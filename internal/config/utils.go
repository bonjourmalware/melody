package config

import "os"

func exists(filepath string) (bool, error) {
	var err error
	if f, err := os.Open(filepath); err != nil {
		_ = f.Close()
		if os.IsNotExist(err) {
			return false, err
		}
	}

	return true, err
}
