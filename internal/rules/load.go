package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func LoadRulesDir(rulesDir string) {
	var globalRawRules GlobalRawRules
	var total uint

	err := filepath.Walk(rulesDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			fmt.Println("Parsing", path)
			if strings.HasSuffix(path, ".yml") {
				globalRawRules = append(globalRawRules, parseYAMLRulesFile(path))
			} else {
				fmt.Println("invalid rule file (wanted : .yml) :", path)
			}

			return nil
		})

	if err != nil {
		fmt.Println(fmt.Sprintf("Failed to parse rule directory [%s]", rulesDir))
		fmt.Println(err)
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

	fmt.Println(fmt.Sprintf("Loaded %d rules", total))
}
