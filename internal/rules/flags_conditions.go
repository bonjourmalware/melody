package rules

import (
	"log"
)

// RawTCPFlags abstracts a string describing raw TCP flags
type RawTCPFlags string

// RawFragbits abstracts a string describing raw fragbits
type RawFragbits string

// RawTCPFlagsList abstracts an array of RawTCPFlags
type RawTCPFlagsList []RawTCPFlags

// RawFragbitsList abstracts an array of RawFragbits
type RawFragbitsList []RawFragbits

// ParseList parses a RawFragbitsList and returns a list of fragbits as an uint8 array
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

// ParseList parses a RawTCPFlagsList and returns a list of tcp flags as an uint8 array
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

// Parse parses a RawTCPFlags string to return its equivalent as an uint8
func (rfls RawTCPFlags) Parse() *uint8 {
	var flags uint8

	//TODO Add support for "Not" option
	for _, val := range rfls {
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

// Parse parses a RawFragbits string to return its equivalent as an uint8
func (rfbs RawFragbits) Parse() *uint8 {
	var fragbits uint8

	if len(rfbs) == 0 {
		return nil
	}

	for _, flag := range rfbs {
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
