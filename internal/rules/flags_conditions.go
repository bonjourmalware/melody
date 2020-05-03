package rules

import (
	"log"
)

type RawTCPFlags string
type RawFragbits string

type RawFragbitsList []RawFragbits
type RawTCPFlagsList []RawTCPFlags

func (list RawFragbitsList) ParseList() []*uint8 {
	var flagsList []*uint8

	if len(list) == 0 {
		return []*uint8{}
	}

	for _, val := range list {
		flagsList = append(flagsList, val.Parse())
	}

	return flagsList
}

func (list RawTCPFlagsList) ParseList() []*uint8 {
	var flagsList []*uint8

	if len(list) == 0 {
		return nil
	}

	for _, val := range list {
		flagsList = append(flagsList, val.Parse())
	}

	return flagsList
}

func (rawFlag RawTCPFlags) Parse() *uint8 {
	var flags uint8

	//TODO Add support for "Not" option
	for _, val := range rawFlag {
		switch val {
		case 'F':
			flags |= 0x01
		case 'S':
			flags |= 0x02
		case 'R':
			flags |= 0x04
		case 'P':
			flags |= 0x08
		case 'A':
			flags |= 0x10
		case 'U':
			flags |= 0x20
		case 'E':
			flags |= 0x40
		case 'C':
			flags |= 0x80
		case '0':
			flags = 0
		default:
			log.Println("Unknown TCP flag value :", val)
			return nil
		}
	}

	return &flags
}

func (rawFlag RawFragbits) Parse() *uint8 {
	var fragbits uint8

	if len(rawFlag) == 0 {
		return nil
	}

	for _, flag := range rawFlag {
		switch flag {
		case 'M':
			fragbits |= 0x01
		case 'D':
			fragbits |= 0x02
		case 'R':
			fragbits |= 0x04
		default:
			log.Println("Unknown fragbits value :", flag)
		}
	}

	return &fragbits
}
