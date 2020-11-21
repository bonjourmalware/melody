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
        version: 1.0
        author: BonjourMalware
        status: stable
        created: 2020/11/07
        modified: 2020/20/07
        description: "Checking or trying to exploit CVE-2020-14882"
        references:
          - "https://nvd.nist.gov/vuln/detail/CVE-2020-14882"
      match:
        http.uri:
          startswith|any|nocase:
            - "/console/css/"
            - "/console/images"
          contains|any|nocase:
            - "console.portal"
            - "consolejndi.portal?test_handle="
      tags:
        cve: "cve-2020-14882"
        vendor: "oracle"
        product: "weblogic"
        impact: "rce"
    ```

!!! Tip
    You can whitelist or blacklist ports and IP addresses with the `whitelist` sections `blacklist` (not shown here).

## Structure

The rules have 7 sections : `layer`, `meta`, `match`, `whitelist`, `blacklist`, `tags` and `embed`.

### layer
The rule will look for matches in the specified `layer`'s protocol data.

Each `layer` expose different fields depending on the protocol they represent. They're detailed in the [Layers](/layers/) page.

The following layers are supported :

|Key|IPv4|IPv6|
|---|---|---|
|http|✅|✅|
|tcp|✅|✅|
|udp|✅|✅|
|icmpv4|✅|❌|
|icmpv6|❌|✅|

!!! important
    A single rule only applies to the targeted layer. Use multiple rules if you want to match multiple layers.

### meta
The `meta` section contains all the rule's metadata. Every keys are mandatory, except `references`. 

|Key|Type|Description|Values|Examples|
|---|---|---|---|---|
|**id**|*string*|Rule's unique identifier. Each rule must have a unique UUIDv4|-|<pre>id: c30370f7-aaa8-41d0-a392-b56c94869128</pre>|
|**version**|*string*|Rule syntax version|1.0|<pre>version: 1.0</pre>|
|**author**|*string*|The name of the rule's author|-|<pre>author: BonjourMalware</pre>|
|**status**|*string*|The status gives an indication of the usability of the rule|stable, experimental|<pre>status: stable</pre>|
|**created**|*yyyy/mm/dd*|Creation date|-|<pre>created: 2020/11/07</pre>|
|**modified**|*yyyy/mm/dd*|Last modification date|-|<pre>modified: 2020/11/07</pre>|
|**description**|*string*|A quick description of what the rule is attempting to match|-|<pre>description: Checking or trying to exploit CVE-2020-14882</pre>|
|**references**|*array*|The status gives an indication of the usability of the rule|-|<pre>references: <br>&nbsp;&nbsp;&nbsp;&nbsp;- "https://nvd.nist.gov/vuln/detail/CVE-2020-14882"<br>&nbsp;&nbsp;&nbsp;&nbsp;- "https://github.com/jas502n/CVE-2020-14882"<br>&nbsp;&nbsp;&nbsp;&nbsp;- ...</pre>|

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

There are 3 types of *conditions* : `number`, `flags` or `complex`. 

##### Number
A number.

!!! Example
    ```yaml
    tcp.window: 512
    ```

!!! Note
    The `number` types takes advantage of YAML to support octal (0o1234), hex (0x1234) and decimal (1234) representation. 

##### Flags

`flags` *condition* are made of a list of flag combination to match.

The *condition* is valid as soon as a match is found (OR).

!!! Example
    ```
    tcp.flags:
      - "PA"
      - "S"
    ```
    
    This rule will match a TCP packet with its flag bits set to "PA" (PSH-ACK, 0x18) or "S" (SYN, 0x2).
    
!!! Note 
    Only two fields support `flags` *condition* : `tcp.flags` and `tcp.fragbits`.

##### Complex

The `complex` *condition* type supports *matching operators* and inline *modifiers*.

To check which fields support `complex` *conditions*, take a look at the [layers documentation](/layers).

###### Matching operators
The *matching operator* specifies how to handle data.

A single *condition* can be made of a set of *matching operators*.

!!! Important
    By default, a rule needs to validate all the *conditions* to match. However, you can specify `any: true` to force a rule to test all of its conditions and return a match as soon as it find a valid one.

!!! Example
    ```yaml
    udp.payload:
      contains:
        - "after all, we're all alike."
      startswith:
        - "Damn kids"
      any: true
    ```
    
    In this example, the *condition* key is `udp.payload` and the *matching operators* are `contains` and `startswith`. 
    
    This rule will match if the payload of an UDP packet startswith the string "Damn kids" OR contains "after all, we're all alike.". 
    
    The rule needs both to match if we remove the `any: true` option.

|Name|Description|
|---|---|
|is|The packet's field value is **strictly equal** to the *condition*'s value|
|contains|The packet's field value **contains** the *condition*'s value|
|startswith|The packet's field value **starts** with the *condition*'s value|
|endswith|The packet's field value **ends** with the *condition*'s value|

###### Modifiers
*Modifiers* are a way to quickly set options for the *matching operator*.

They live on the same line, split by `|`. All *modifiers* can be mixed at once.

!!! Important
    By default, a *condition* needs to match all of the given values (AND). However, you can use the `|any` *modifier* to reverse it and force it to test all the values and to return on the first match.

!!! Example
    ```yaml
    http.body:
      contains|any|nocase:
        - "Enter my world"
        - "the beauty of the baud"
    ```
    
    In this example, the *modifiers* are `any` and `nocase`. This rule will match if the URI field of an HTTP packet contains any item in the list.

|Name|Description|Example|
|---|---|---|
|any|The rule match if **any** of the values in the list matches|-|
|nocase|The match is **case insensitive**|abcd == aBcD == ABCD|
|regex|The value is a **regular expression**|'(?:[0-9]{1,3}\.){3}[0-9]{1,3}' == 192.0.2.1|

!!! Danger
    Although the regex is compiled only once, it can cause severe overhead while matching packets. Use it with caution.

###### Hybrid pattern

`complex` *condition*'s support hex values by wrapping them between two `|`.

You can mix hex and ascii in a single string as well.

!!! Example
    ```yaml
    http.body:
      contains:
        - "|45 6e 74 65 72206d79| world"
    ```
    
    !!! Note
        '0x' hex notation (`|0xbe 0xef|`) is invalid. You can mix spaced and not spaced hex bytes though.

### Whitelist and blacklist

These two fields can be used to filter the packets on which the rule is applied.

IP source addresses and ports are supported.

#### IP address

!!! Example
    ```yaml
    whitelist:
      ips:
        - 127.0.0.1
    ```
    
    This example only tries to match the packets coming from 127.0.0.1.

    ```yaml
    blacklist:
      ips:
        - 127.0.0.1
    ```
    
    Use the blacklist keyword to reverse the logic and apply the rule to all packets but the one coming from 127.0.0.1.

!!! Example
    ```yaml
    whitelist:
      ips:
        - 127.0.0.0/24
    ```
    
    CIDR notation supported.

#### Ports

!!! Example
    ```yaml
    whitelist:
      ports:
        - 80
    ```
    
    This example only tries to match the packets going to port 80 .

    ```yaml
    blacklist:
      ports:
        - 80
    ```
    
    Use the blacklist keyword to reverse the logic and apply the rule to all packets but the one going to port 80.

!!! Example
    ```yaml
    whitelist:
      ports:
        - 8000 - 9000
    ```
    
    Port ranges are supported. You can choose to put spaces or not.

### tags
Each of the key/value pair in the `tags` object will be appended to the `matches` field of each of the matching packets.

### embed
This is a block where the user can will embed any data in the `embedded` key of the matching packet. It can be used as an alternative to `tags` to add contextual information.

!!! Example
    ```yaml
    embed:
      my_crime: "curiosity"
      ...
    ```
