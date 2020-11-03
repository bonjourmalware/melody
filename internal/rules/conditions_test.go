package rules

import (
	"bytes"
	"fmt"
	"testing"
)

func TestParseHybridPattern(t *testing.T) {
	tests := []struct {
		OkSrc  []string
		NokSrc []string
		OkDst  [][]byte
		NokDst [][]byte
		ErrSrc []string
		ErrDst []string
	}{
		{
			OkSrc: []string{
				"abcd1234abcd",
				"abcd1234|0d0a|abcd",
				"abcd1234|0d 0a|abcd",
				"abcd1234|0d 0a|",
				"|0d 0a|abcd",
			},
			OkDst: [][]byte{
				{97, 98, 99, 100, 49, 50, 51, 52, 97, 98, 99, 100},
				{97, 98, 99, 100, 49, 50, 51, 52, 13, 10, 97, 98, 99, 100},
				{97, 98, 99, 100, 49, 50, 51, 52, 13, 10, 97, 98, 99, 100},
				{97, 98, 99, 100, 49, 50, 51, 52, 13, 10},
				{13, 10, 97, 98, 99, 100},
			},
			NokSrc: []string{
				"abcd1234|0b0a|abcd",
			},
			NokDst: [][]byte{
				{97, 98, 99, 100, 49, 50, 51, 52, 97, 98, 99, 100},
			},
			ErrSrc: []string{
				"abcd12340d0a|abcd",
				"abcd12340d|0x0a 0x0d|abcd",
			},
			ErrDst: []string{
				fmt.Sprintf("failed to parse hybrid pattern : uneven number of hex delimiter (\"|\") in %s", "abcd12340d0a|abcd"),
				fmt.Sprintf("failed to parse hybrid pattern : [%s] in %s", "encoding/hex: invalid byte: U+0078 'x'", "abcd12340d|0x0a 0x0d|abcd"),
			},
		},
	}

	for _, suite := range tests {
		for idx, val := range suite.OkSrc {
			parsed, err := ParseHybridPattern([]byte(val))
			if err != nil {
				t.Error(val, ":", err, "FAILED")
				t.Fail()
				continue
			}
			if !bytes.Equal(parsed, suite.OkDst[idx]) {
				t.Error(val, "FAILED")
				t.Fail()
			}
		}

		for idx, val := range suite.NokSrc {
			parsed, err := ParseHybridPattern([]byte(val))
			if err != nil {
				t.Error(val, ":", err, "FAILED")
				t.Fail()
				continue
			}
			if bytes.Equal(parsed, suite.NokDst[idx]) {
				t.Error(val, "FAILED")
				t.Fail()
			}
		}

		for idx, val := range suite.ErrSrc {
			parsed, err := ParseHybridPattern([]byte(val))
			if err == nil {
				t.Error(val, "FAILED : got no error")
				t.Fail()
				continue
			}
			if parsed != nil {
				t.Error(val, "FAILED : parsed value is not empty")
				t.Fail()
				continue
			}

			if err.Error() != suite.ErrDst[idx] {
				t.Error(val, ":", err, "FAILED")
				t.Fail()
			}

		}
	}
}

func TestParseOptions(t *testing.T) {
	var cond Conditions
	emptyOption := Options{}

	tests := []struct {
		OkSrc  []string
		NokSrc []string
		OkDst  []Options
		NokDst []Options
		ErrSrc []string
		ErrDst []string
	}{
		{
			OkSrc: []string{
				"contains",
				"any|contains",
				"contains|any",
				"endswith|any",
				"startswith|any",
				"is|any",
				"contains|any|regex|nocase",
			},
			OkDst: []Options{
				{
					All:      true,
					Contains: true,
				},
				{
					All:      false,
					Contains: true,
				},
				{
					All:      false,
					Contains: true,
				},
				{
					All:      false,
					Endswith: true,
				},
				{
					All:        false,
					Startswith: true,
				},
				{
					All: false,
					Is:  true,
				},
				{
					All:      false,
					Contains: true,
					Regex:    true,
					Nocase:   true,
				},
			},
			NokSrc: []string{
				"any|contains",
				"contains",
			},
			NokDst: []Options{
				{
					All: false,
				}, {
					All: true,
				},
			},
			ErrSrc: []string{
				"contains|is",
				"contains|nonexistent",
				"",
			},
			ErrDst: []string{
				fmt.Sprintf("options parsing failed for condition %s : there can only be one of <is|contains|startswith|endswith>\n", "contains|is"),
				fmt.Sprintf("options parsing failed for condition %s : unknown option \"%s\"\n", "contains|nonexistent", "nonexistent"),
				fmt.Sprintf("options parsing failed for condition %s : matching mode cannot be empty\n", ""),
			},
		},
	}

	cond = Conditions{}

	for _, suite := range tests {
		for idx, val := range suite.OkSrc {
			err := cond.ParseOptions(val)
			if err != nil {
				t.Error(val, "FAILED :", err)
				t.Fail()
				continue
			}
			if cond.Options != suite.OkDst[idx] {
				t.Error(val, "FAILED")
				t.Fail()
				continue
			}
		}

		cond = Conditions{}

		for _, suite := range tests {
			for idx, val := range suite.NokSrc {
				err := cond.ParseOptions(val)
				if err != nil {
					t.Error(val, "FAILED :", err)
					t.Fail()
					continue
				}
				if cond.Options == suite.NokDst[idx] {
					t.Error(val, "FAILED")
					t.Fail()
					continue
				}
			}
		}

		cond = Conditions{}
		for _, suite := range tests {
			for idx, val := range suite.ErrSrc {
				err := cond.ParseOptions(val)
				if err == nil {
					t.Error(val, "FAILED : got no error")
					t.Fail()
					continue
				}
				if cond.Options != emptyOption {
					t.Error(val, "FAILED : parsed value is not empty")
					t.Fail()
					continue
				}
				if err.Error() != suite.ErrDst[idx] {
					t.Error(val, ":", err, "FAILED")
					t.Fail()
				}
			}
		}
	}
}

//TODO Tests of the logic flow when having multiple condition bloc
