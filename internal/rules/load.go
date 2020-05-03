package rules

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

var (
	GlobalRules []Rules
)

type GlobalRawRules []RawRules

func LoadRulesDir(rulesDir string) {
	var globalRawRules GlobalRawRules
	var total uint

	skiplist := []string{
		".gitkeep",
	}

	err := filepath.Walk(rulesDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			for _, skipped := range skiplist {
				if info.Name() == skipped {
					return nil
				}
			}

			log.Println("Parsing", path)
			if strings.HasSuffix(path, ".yml") {
				parsed, err := ParseYAMLRulesFile(path)
				if err != nil {
					log.Println(fmt.Sprintf("Failed to read YAML rule file [%s]", path))
					log.Println(err)
					os.Exit(1)
				}
				globalRawRules = append(globalRawRules, parsed)
			} else {
				log.Println("invalid rule file (wanted : .yml) :", path)
			}

			return nil
		})

	if err != nil {
		log.Println(fmt.Sprintf("Failed to parse rule directory [%s]", rulesDir))
		log.Println(err)
		os.Exit(1)
	}

	for _, rawRules := range globalRawRules {
		var rules Rules
		for ruleName, rawRule := range rawRules {
			var rule Rule
			rule = rawRule.Parse()
			rule.Name = ruleName

			rules = append(rules, rule)
		}

		GlobalRules = append(GlobalRules, rules)
	}

	for _, ruleset := range GlobalRules {
		total += uint(len(ruleset))
	}

	log.Println(fmt.Sprintf("Loaded %d rules", total))
}

func ParseYAMLRulesFile(filepath string) (RawRules, error) {
	rawRules := RawRules{}
	rulesData, err := ioutil.ReadFile(filepath)
	if err != nil {
		return RawRules{}, err
	}

	if err := yaml.Unmarshal(rulesData, &rawRules); err != nil {
		return RawRules{}, err
	}

	return rawRules, nil
}
