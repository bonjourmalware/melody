## Description

Meloctl is a helper program that streamlines the use of Melody and its ecosystem by providing features such as validation checks for Melody's configuration and rule files.

```
Melody helper

Usage:
  meloctl [command]

Available Commands:
  config      Interact with a Melody config file
  get         Get a Meloctl config value by name
  help        Help about any command
  init        Create Meloctl config
  rule        Handle Melody rule files
  set         Set a Meloctl config value by name

Flags:
  -h, --help   help for meloctl

Use "meloctl [command] --help" for more information about a command.
```

## Initilization

For better user experience, you'll need to store basic information such as Melody's home dir in a configuration file before starting. 

To do so, run `meloctl init` to start the interactive prompt.

## Features
### config
#### check

Check a rule file or a directory containing multiple files  

Example : 

```
$ ./meloctl config check ./config.yml 
✅ [./config.yml]: OK
```

### rule
#### check

Validate the YAML syntax and look for unknown properties or fields.

```
$ ./meloctl rule check ./rules/rules-available 
❌ [rules/rules-available/cms.yml]: unknown property 'http.uri|nonexistent'
✅ [rules/rules-available/microsoft.yml]: OK
❌ [rules/rules-available/nas.yml]: yaml: line 2: did not find expected key
✅ [rules/rules-available/rdp.yml]: OK
✅ [rules/rules-available/router.yml]: OK
✅ [rules/rules-available/server.yml]: OK
✅ [rules/rules-available/vpn.yml]: OK
✅ [rules/rules-available/web.yml]: OK
```

#### init

Bootstrap a rule with an automatically pre-filled template.

Usage :

```
Usage:
  meloctl rule init [flags]

Flags:
  -a, --author string            Author field for new rule (default "Changeme")
  -d, --description string       Description field for new rule
  -f, --force                    Do not ask permission to overwrite if a rule already defined
  -h, --help                     help for init
  -i, --interactive              Ask for each parameter for the new rule
  -l, --layer string             Layer field for new rule (default "http")
  -n, --name string              Name field for new rule (default "Changeme")
  -r, --references stringArray   References fields new rule
  -s, --status string            Status field for new rule (default "experimental")
  -t, --tags stringToString      Tags fields for new rule (default [])

```

Default template :

```
$ ./meloctl rule init demo.yml
Writing :
 Changeme:
    layer: http
    meta:
        version: "1.0"
        id: 6ddbbfaa-72c1-41d8-bb78-34111286a8d2
        author: Changeme
        status: experimental
        created: 2021/04/19
        modified: 2021/04/19
        description: ""
    match:
        http.uri:
            contains|nocase:
                - ""
            endswith:
                - ""
            is|regex:
                - ""
            startswith|any:
                - ""
    references: []
    tags: {}

✅ [/opt/melody/demo.yml]: Rule file created
```

You can use the interactive mode (`-i`), give specific values, or even mix both :

```
$ ./meloctl rule init demo.yml -i --name "Demo rule" --status testing --tag "purpose=demo" --tag "teapot.state=empty"
Use the arrow keys to navigate: ↓ ↑ → ← 
? Layer: 
  ▸ http
    icmp
    tcp
    udp
    ip
✔ http
✔ Version: 1.0
Author: Changeme
Use the arrow keys to navigate: ↓ ↑ → ← 
? Status: 
    stable
    experimental
  ▸ testing
✔ testing
Created: 2021/04/19
Modified: 2021/04/19
✔ Description: This is a demo rule

Writing :
 Demo rule:
    layer: http
    meta:
        version: "1.0"
        id: 8738f81c-35d4-45f0-b553-c9d9c8993e4c
        author: Changeme
        status: testing
        created: 2021/04/19
        modified: 2021/04/19
        description: ""
    match:
        http.uri:
            contains|nocase:
                - ""
            endswith:
                - ""
            is|regex:
                - ""
            startswith|any:
                - ""
    references: []
    tags:
        purpose: demo
        teapot.state: empty

✅ [/opt/melody/demo.yml]: Rule file created
```

#### add

This command will do the same as `init`, except the new rule will be appended to the specified file.

### init

```
$ ./meloctl init
Melody home directory: /opt/melody
✅ [~/.config/meloctl/meloctl.yml] Meloctl has been initialized
```

### get

```
$ ./meloctl get melody.home
melody.home => /opt/melody 
```

### set

```
$ ./meloctl set melody.home /opt/melody
melody.home => /opt/melody 
✅ [~/.config/meloctl/meloctl.yml] Configuration file updated
```