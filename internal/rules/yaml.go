package rules

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
)

func parseYAMLRulesFile(filepath string) RawRules {
	rawRules := RawRules{}
	rulesData, err := ioutil.ReadFile(filepath)
	if err != nil {
		fmt.Println(fmt.Sprintf("Failed to read YAML rule file [%s]", filepath))
		fmt.Println(err)
		os.Exit(1)
	}

	if err := yaml.Unmarshal(rulesData, &rawRules); err != nil {
		fmt.Printf("Failed to load the YAML rule file [%s]\n", filepath)
		fmt.Println(err)
		os.Exit(1)
	}

	return rawRules
}