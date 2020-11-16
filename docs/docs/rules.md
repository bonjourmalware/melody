Melody rules are used to apply tags on matching packets. They have multiple use cases, such as monitoring emerging threats, automated droppers, vulnerability scanners...

Take a look in the `$melody/rule-available` and `$melody/internal/rules/test_resources` folders to quickly find working examples. 

## First look

A rule file can contain multiple rule descriptions. 

!!! Example
    This example detects CVE-2020-14882 (Oracle Weblogic RCE) scans or exploitation attempts by matching either of the two URI on the HTTP level :
    
    ```yaml
    CVE-2020-14882 Oracle Weblogic Server RCE:
      layer: http
      meta:
        id: 3e1d86d8-fba6-4e15-8c74-941c3375fd3e
        author: BonjourMalware
        status: stable
        created: 2020/11/07
        modified: 2020/11/07
        description: "Checking or tying to exploit CVE-2020-14882"
        references:
          - "https://nvd.nist.gov/vuln/detail/CVE-2020-14882"
      match:
        http.method:
          is:
            - "POST"
        http.uri:
          contains|any:
            - "/console/images/%252E%252E%252Fconsole.portal"
            - "/console/css/%2e"
      tags:
        cve: "cve-2020-14882"
        vendor: "oracle"
        product: "weblogic"
        impact: "rce"
    ```

## Structure

The rules have 5 sections : `layer`, `meta`, `match`, `tags` and `embed`.

### layer
The rule will look for matches in the specified `layer`'s protocol data.

Each layer expose different fields depending on the protocol they represent. They're detailed in the [Layers](/layers/) page.

The following layers are supported by Melody :

|Key|IPv4|IPv6|
|---|---|---|
|http|✅|✅|
|tcp|✅|✅|
|udp|✅|✅|
|icmpv4|✅|❌|
|icmpv6|❌|✅|

!!! important
    You must keep in mind that a rule only applies to a single layer. Use multiple rules to look for the same thing in different layers.

### meta
The `meta` section contains all the rule's metadata. Every key are mandatory, except `references`. 

|Key|Type|Description|Values|Examples|
|---|---|---|---|---|
|**id**|*string*|Rule's unique identifier. Each rule must have a unique UUIDv4|-|id: c30370f7-aaa8-41d0-a392-b56c94869128|
|**author**|*string*|The name of the rule's author|-|author: BonjourMalware|
|**status**|*string*|The status gives an indication of the usability of the rule|stable, experimental|status: stable|
|**created**|*yyyy/mm/dd*|Creation date|-|created: 2020/11/07|
|**modified**|*yyyy/mm/dd*|Last modification date|-|modified: 2020/11/07|
|**description**|*string*|A quick description of what the rule is attempting to match|-|description: Checking or tying to exploit CVE-2020-14882|
|**references**|*array*|The status gives an indication of the usability of the rule|-|references: <br>&nbsp;&nbsp;&nbsp;&nbsp;- "https://nvd.nist.gov/vuln/detail/CVE-2020-14882"<br>&nbsp;&nbsp;&nbsp;&nbsp;- "https://github.com/jas502n/CVE-2020-14882"<br>&nbsp;&nbsp;&nbsp;&nbsp;- ...|

!!! Important
    You must generate a new UUIDv4 for the `id` of every rule you create.
    
    Sample code for Python :
    ```python
    import uuid

    print(uuid.uuid4())
    ```

    Go ([playground](https://play.golang.org/p/9qDBHpZ2QqY)) :
    ```go
    package main

    import (
        "fmt"
        "github.com/google/uuid"
    )
    
    func main(){
        fmt.Println(uuid.New())
    }
    ```

### match
The `match` block contains a set of *conditions* that will be checked on every packet of the rule's `layer` type.

Here is the structure of the `match` section :

```yaml
match:
  any: [true|false]                 # false by default
  field1:                           # complex condition
    any: [true|false]               # false by default
    operator1|modifier1|modifier2:  # matching operator with its modifiers
      - value1
      - value2
    operator2:
      - value
  field2:                           # array condition
    - value1
    - value2
  field3: value                     # string or number condition
```

#### Conditions
A *condition* corresponds to a field in a packet, specified by its name.

The available *conditions* depends on the `layer` key. The keys are namespaced according to the type they belong to.

!!! Example
    `udp.payload`, `tcp.flags`, `http.uri`...

There are 4 types of *condition* types : `string`, `number`, `array` or `complex`. 

The `complex` *condition* type supports *matching operators* and inline *modifiers*.

Check the layer's documentation to see which fields support `complex` *conditions*.

!!! Note
    The `number` types takes advantage of YAML to support octal (0o1234), hex (0x1234) and decimal (1234) representation. 
    
!!! Warning
     However, the `string` type fields does not support hex notation.

#### Matching operators
The *matching operator* specifies how to handle data.

A single *condition* can be made of a set of *matching operators*.

!!! Important
    By default, a rule needs to validate all the *conditions* to match. However, you can specify `any: true` to force a rule to test all of its ccondition and match as soon as it find a valid one.

!!! Example
    ```yaml
    udp.payload:
      contains:
        - "after all, we're all alike."
    ```
    
    In this example, the *condition* key is `udp.payload` and the *matching operator* is `contains`.
    
    This rule will match if the verb of an HTTP packet is exactly `POST`.

|Name|Description|
|---|---|
|is|The packet's field value is **strictly equal** to the *condition*'s value|
|contains|The packet's field value **contains** the *condition*'s value|
|startswith|The packet's field value **starts** with the *condition*'s value|
|endswith|The packet's field value **ends** with the *condition*'s value|

#### Modifiers
*Modifiers* are a way to quickly set options for the *matching operator*.

They live on the same line, split by `|`. All *modifiers* can be mixed at once.

!!! Important
    By default, a *condition* needs to validate all of its values to match. However, you can use the `|any` *modifier* to force a condition to test all of its values and to be validated on the first match.

!!! Example
    ```yaml
    http.uri:
      contains|any:
        - "/console/images/%252E%252E%252Fconsole.portal"
        - "/console/css/%2e"
    ```
    
    In this example, the *modifier* is `any`. This rule will match if the URI field of an HTTP packet contains any item in the list.

|Name|Description|Example|
|---|---|---|
|any|The rule match if **any** of the values in the list matches|-|
|nocase|The match is **case insensitive**|abcd == aBcD == ABCD|
|regex|The value is a **regular expression**|'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' == 192.0.2.1|

!!! Danger
    Although the regex is compiled only once, it can cause severe overhead while matching packets. Use it with caution.

#### Hybrid pattern

`complex` *condition*'s values support hex representation of strings by wrapping them in two `|`.

You can mix hex and ascii in a single string as well.

!!! Example
    ```yaml
    http.body:
      contains:
        - "|45 6e 74 65 72206d79| world"
    ```
    
    !!! Note
        `0xbeef` notation is invalid. You can mix spaced and not spaced hex bytes though.


### tags
Each of the key/value pair in the `tags` object will be appended to the `matches` field of each of the matching packets.

### embed
This is a block where the user can will embed any data in the `embedded` key of the matching packet. It can be used as an alternative to `tags` to add contextual information.

!!! Example
    ```yaml
    embed:
      key1: "value1"
      key2: "value2"
    ```
