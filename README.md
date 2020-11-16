<p align="center">
  <h1 align="center">Melody</h1>
  <p align="center">Monitor the Internet's background noise</p>
</p>

<p align="center">
    <a href="https://goreportcard.com/badge/github.com/bonjourmalware/melody"><img src="https://goreportcard.com/badge/github.com/bonjourmalware/melody" alt="Go Report Card"/></a>
    <a href="https://coveralls.io/github/bonjourmalware/melody"><img src="https://coveralls.io/repos/github/bonjourmalware/melody/badge.svg" alt="Coverage Status"/></a>
    <a href="https://hub.docker.com/r/bonjourmalware/melody/builds"><img src="https://img.shields.io/docker/cloud/build/bonjourmalware/melody" alt="Docker build status"/></a>
    <a href="https://hub.docker.com/r/bonjourmalware/melody/builds"><img src="https://img.shields.io/docker/image-size/bonjourmalware/melody" alt="Docker image size"/></a>
    <a href="https://hub.docker.com/r/bonjourmalware/melody/builds"><img src="https://img.shields.io/docker/cloud/automated/bonjourmalware/melody" alt="Docker automated build"/></a>
</p>

<p align="center">
    <a href="https://bonjourmalware.github.io/melody/"><img src="https://img.shields.io/badge/%F0%9F%93%9A-Documentation-informational" alt="Documentation"/></a>
    <a href="https://bonjourmalware.github.io/melody/installation"><img src="https://img.shields.io/badge/%F0%9F%93%9A-Installation-informational" alt="Installation"/></a>
    <a href="https://bonjourmalware.github.io/melody/quickstart"><img src="https://img.shields.io/badge/%F0%9F%93%9A-Quickstart-informational" alt="Quickstart"/></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="Go Report Card"/></a>
</p>

----

Melody is a transparent internet sensor built for threat intelligence and supported by a detection rule framework which allows you to tag packets of interest for further analysis and threat monitoring.

# Features
Here are some key features of Melody :

+ Transparent capture
+ Write detection rules and tag specific packets to analyze them at scale 
+ Mock vulnerable websites using the builtin HTTP/S server
+ Supports all the main internet protocols over IPv4 and IPv6
+ Handles log rotation for you : Melody is designed to be able to run forever on the smallest VPS
+ Minimal configuration required
+ Standalone mode : configure Melody using only the CLI
+ Easily scalable :
    + Statically compiled binary
    + Up-to-date Docker image 

Additional features on the roadmap include :

+ Dedicated helper program to create, test and manage rules
+ Centralized rules management

# Rules

[Rule syntax details.](https://bonjourmalware.github.io/melody/installation)

## Rule example

```yaml
CVE-2020-14882 Oracle Weblogic Server RCE:
  layer: http
  meta:
    id: 3e1d86d8-fba6-4e15-8c74-941c3375fd3e
    author: BonjourMalware
    status: stable
    created: 2020/11/07
    modified: 2020/11/07
    description: "Checking or trying to exploit CVE-2020-14882"
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
