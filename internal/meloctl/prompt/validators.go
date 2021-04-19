package prompt

import (
	"time"
)

var (
	validatorsMap = map[string]func(candidate string) error{
		"date": checkDate,
	}

	// DateFormat is the format used to validate dates inputs from the user
	DateFormat = "2006/01/02"
)

func checkDate(candidate string) error {
	_, err := time.Parse(DateFormat, candidate)
	if err != nil {
		return err
	}

	return nil
}
