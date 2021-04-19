package tagparser

import (
	"reflect"

	"github.com/fatih/structtag"
)

// ParseYamlTagValue parses a tag to retrieve the value of its yaml key
func ParseYamlTagValue(tag reflect.StructTag) (string, error) {
	parsedRuleTags, err := structtag.Parse(string(tag))
	if err != nil {
		return "", err
	}

	yamlTag, err := parsedRuleTags.Get("yaml")
	if err != nil {
		return "", err
	}
	return yamlTag.Value(), nil
}
