# Quickstart
## Before we start

Hi !

You'll need the following info :

+ The name of the interface on which you want Melody to listen to 
    + wlp3s0, ens3, enp0s25, eth0...
+ All the IP addresses to exclude from monitoring

!!! Tip
    Don't forget to exclude the IP from which you're SSH'ing

Clone the repo to get the default rules and configuration files :

```git
git clone https://github.com/bonjourmalware/melody
```

!!! Tip
    You can also write the configuration files later or use CLI options to use it as a standalone binary

## Firewall
Don't forget to check your firewall state to ensure you're not blocking packets from reaching the sensor.

## Build from source
Build Melody with :

```
make build
```

or

```
go build -ldflags="-s -w -extldflags=-static" -o melody
sudo setcap cap_net_raw,cap_setpcap=ep ./melody
```

!!! warning
    You need the libpcap headers before building Melody. Install them with :
    ```bash
    sudo apt update
    sudo apt install libpcap-dev
    ```

## Grab a release

You can grab the latest release by visiting https://github.com/bonjourmalware/melody/releases/latest.

## Docker
You can also use Docker and pull the image from Docker Hub :

```
docker pull bonjourmalware/melody:latest
```

# Configuration
## Melody configuration
All the available configuration options are listed with their default values in the `config.yml` file.

You'll want to look at a few things before getting started :

+ Set the `listen.interface` to the one on which you want Melody to be listening on

!!! Tip
    On most recent linux distribution, you can run `route | grep '^default' | grep -o '[^ ]*$'` to find the default WAN card.

!!! Tip
    On Windows, you'll want an interface name like `\Device\NPF_{4E273621-5161-46C8-895A-48D0E52A0B83}`.
    
    If you find an interface name with `TCP` in place of `NPF`, try swaping both.
    
    See [Find Windows interfaces]()
     
    Don't forget to wrap your string with `'` to prevent the parsing of the escaping `\`.

!!! Note
    Note that Melody listen on `lo` by default. You can override the listening interface with the `-i` switch.

+ The dummy HTTP/S servers are enabled by default. Disable it if you're not interested by this data, or you're putting Melody next to a web application

+ Default rules are disabled by default. You can enable them by creating a symlink for each rule to enable in the active rule directory specified in the configuration file (`$melody/rules/rules-enabled` by default)

!!! Tip
    To create a symlink, use the following command from the root of the projet :
    ```bash
    ln -rs ./rules/rules-available/$rule.yml ./rules/rules-enabled/
    ```
    
    Use a wildcard to enable all the rulesets :
    ```bash
    ln -rs ./rules/rules-available/*.yml ./rules/rules-enabled/
    ```

## HTTP/S server
In order to capture the full HTTP transactions, the client must have a server to connect to. To ease that process, a dummy HTTP/S server is available.

Its default configuration is to answer `200 OK` on every routes, with a `Server: Apache` header.

### iptables

To capture the HTTP traffic your server receives on every ports, we advise you to use `iptables` to redirect the data from every ports to the one Melody is listening on.

!!! Danger
    Be very careful while applying these modifications. You must at least exclude your remote connection port using the `! --dports ` switch, or you will be locked out. 

To achieve this, add a rule to your `PREROUTING` table :

```
sudo iptables -A PREROUTING -t nat -i $INTERFACE -p tcp -m multiport ! --dports $REMOTE_ACCESS_PORT,$ANOTHER_EXCLUDED_PORT -j REDIRECT --to-port $MELODY_HTTP_PORT
```

Example : 

```
sudo iptables -A PREROUTING -t nat -i ens3 -p tcp -m multiport ! --dports 1234,5678 -j REDIRECT --to-port 10800
```

Here the ports `1234` and `5678` have been excluded from the redirection.

!!! Note
    Using the `sudo iptables -t nat -L PREROUTING -n -v` command, you should see something like this :
    ```
    Chain PREROUTING (policy ACCEPT 1226K packets, 57M bytes)
     pkts bytes target     prot opt in     out     source               destination         
      25M 1243M REDIRECT   tcp  --  ens3   *       0.0.0.0/0            0.0.0.0/0            multiport dports  !1234,5678 redir ports 10800
    ``` 
    
!!! Important
    This is only used to virtually connect the HTTP server to all the ports.
    
    As Melody sits on the data link layer, the program will receive the packets before being handled by network layer programs such as `iptables` or `ufw`. 

# Berkley Packet Filter (BPF)

Next you need to customize the `filter.bpf` file. **This is where you filter the data that reaches Melody.**

By default, only inbound traffic is allowed and all 127.0.0.0/24 subnet banned. 

!!! Note
    You can use the `-f` switch to set a filter via CLI.    

!!! Tip
    If you're using a VPS, you might need to filter out the source IP of the servers used by your hosting provider to check the status of your server. 

## Source IP filtering
Use `[src|dst] net <network>` to filter packets according to their IP.

Example :

```bpf
inbound and not net 127.0.0.1
```

You can specify a range to exclude using the CIDR notation :

```bpf
inbound and not net 127.0.0.0/24
```

## Port filtering
Use `[src|dst] port <port>` to filter packets according to their port.

Example :

```bpf
not port 1234
```

You can specify a range to exclude using the CIDR notation and the `portrange` keyword :

```bpf
not portrange 1234-5678
```

Your `filter.bpf` should look like this :

```
inbound
and not port 1234
and not net 127.0.0.0/24
and not net 192.0.2.1
```

!!! Important
    Your file should always start with the `inbound` keyword. We recommend adding your filter rules below, starting with an `and` keyword.


## Advanced

[Here is all you need to know about the BPF syntax](https://biot.com/capstats/bpf.html) and [here is a great source of examples to get quickly started](https://www.ibm.com/support/knowledgecenter/SS42VS_7.4/com.ibm.qradar.doc/c_forensics_bpf.html).

# Rules

Melody rules are used to apply tags on matching packets. They have multiple use cases, such as monitoring emerging threats, automated droppers, vulnerability scanners...

You can look into the `$melody/rules/rule-available` and `$melody/internal/rules/test_resources` folders to quickly find working examples. 

## Basics

A rule file can contain multiple rules description and constitute a ruleset. 

Here is a rule example that detects CVE-2020-14882 (Oracle Weblogic RCE) scans or exploitation attempts by matching either of the two URI and the HTTP verb :

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

This rule is part of the default `server.yml` ruleset.

If a packet match, the tags will be appended to the `matches` field in the packet's log.

The rules options and the available properties by layer type are described in the [Rules section.](/rules)

!!! Important
    You must generate a new UUIDv4 [for each rule you create](/rules#meta).

## Output

You can redirect the output to stdout by using the `-s` switch.

All the console messages are printed to stderr in order to allow piping Melody's data into `jq`.

A dump mode is also available. Similar to `tcpdump`, it will print raw formated packets to stdout instead of Melody json lines.
    