package prompt

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/fatih/structtag"

	"github.com/manifoldco/promptui"
)

// AskAll prompts the user for each property with a 'pretty' tag
func AskAll(what interface{}, target *map[string]string) error {
	for i := 0; i < reflect.TypeOf(what).NumField(); i++ {
		var choices []string

		tag := reflect.TypeOf(what).Field(i).Tag
		parsedTag, err := structtag.Parse(string(tag))
		if err != nil {
			return err
		}

		yamlTag, err := parsedTag.Get("yaml")
		if err != nil {
			return err
		}

		// iterate over all tags
		prettyTag, _ := parsedTag.Get("pretty")

		if prettyTag == nil {
			continue
		}

		choicesTag, _ := parsedTag.Get("choices")
		if choicesTag != nil {
			choices = strings.Split(choicesTag.Value(), ",")
		}

		validateModeTag, _ := parsedTag.Get("validate")
		hintTag, _ := parsedTag.Get("hint")

		prompt := prettyTag.Value()
		if hintTag != nil {
			prompt = fmt.Sprintf("%s (%s)", prettyTag, hintTag.Value())
		}

		defaultVal := (*target)[yamlTag.Value()]

		if len(choices) > 0 {
			_, res, err := askSelect(prompt, choices, defaultVal)
			if err != nil {
				//log.Fatalln(err.Error())
				return err
			}
			(*target)[yamlTag.Value()] = res
			continue
		}

		if validateModeTag != nil {
			validateFn, ok := validatorsMap[validateModeTag.Value()]
			if !ok {
				//log.Fatalln(fmt.Errorf("unknown validator : %s", validateModeTag.Value()))
				return fmt.Errorf("unknown validator : %s", validateModeTag.Value())
			}

			res, err := askString(prompt, defaultVal, &validateFn)
			if err != nil {
				//log.Fatalln(err.Error())
				return err
			}
			(*target)[yamlTag.Value()] = res
			continue
		}

		res, err := askString(prompt, defaultVal, nil)
		if err != nil {
			return err
		}

		(*target)[yamlTag.Value()] = res
	}

	return nil
}

//func askStringArray(what string, defaultVal string, validateFn *func(candidate string) error) ([]string, error) {
//	var answers []string
//
//	answer, err := askString(what, defaultVal, validateFn)
//	if err != nil {
//		return answers, err
//	}
//	answers = append(answers, answer)
//
//	for {
//		ok, err := AskConfirmation("Add another one ?", true)
//		if err != nil {
//			return answers, err
//		}
//		if !ok {
//			break
//		}
//
//		answer, err := askString(what, defaultVal, validateFn)
//		if err != nil {
//			return answers, err
//		}
//		answers = append(answers, answer)
//	}
//
//	return answers, nil
//}

func askSelect(what string, choices []string, defaultVal string) (int, string, error) {
	var found bool
	var val string
	var idx int
	var cursorPos int

	for idx, val = range choices {
		if defaultVal == val {
			found = true
			break
		}
	}

	if found {
		cursorPos = idx
	}

	prompt := promptui.Select{
		Label:     what,
		Items:     choices,
		CursorPos: cursorPos,
	}

	return prompt.Run()
}

//
//func askString(what string, defaultVal string) (string, error) {
//	prompt := promptui.Prompt{
//		Label:     what,
//		Default:   defaultVal,
//		AllowEdit: true,
//	}
//
//	return prompt.Run()
//}

//
//func askStringArray(what string, defaultVal []string) (string, error) {
//
//
//	prompt := promptui.Prompt{
//		Label: what,
//		Default: defaultVal,
//		AllowEdit: true,
//	}
//
//	return prompt.Run()
//}

func askString(what string, defaultVal string, validateFn *func(candidate string) error) (string, error) {
	var res string
	var err error

	prompt := promptui.Prompt{
		Label:     what,
		Default:   defaultVal,
		AllowEdit: true,
	}

	if validateFn != nil {
		prompt.Validate = *validateFn
	}

	res, err = prompt.Run()
	if err != nil {
		return res, err
	}

	return res, err
}

// AskConfirmation prompts the user for confirmation
func AskConfirmation(what string, defaultChoice bool) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	loop := true

	defaultIndicator := "[Y/n]"
	choice := defaultChoice
	if !defaultChoice {
		defaultIndicator = "[y/N]"
	}

	for loop {
		fmt.Printf("%s %s : ", what, defaultIndicator)
		res, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}

		res = strings.ToLower(strings.TrimSpace(res))

		if res == "y" || res == "yes" {
			choice = true
			loop = false
		} else if res == "n" || res == "no" {
			choice = false
			loop = false
		} else if res == "" {
			loop = false
		}
	}
	return choice, nil
}
