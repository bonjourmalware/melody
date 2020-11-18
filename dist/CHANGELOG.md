

## Changelog

c6a0147 Added BPF cli override
16406b9 Added CI
8d66489 Added CVE-2020-14882 detection rule
40a54b8 Added Dockerfile
d9263ac Added HTTPS support and "tls" test. Added destination ports tests. Added source IP test
21fa1e1 Added HomeNet6 confi key to filter out outgoing packets in IPv6. Added tests for ICMPv6
22b8def Added HomeNet6 to config sample
e4b4d40 Added ICMPv4 tests. Goroutines now exit correctly on error. Added a "dump" option to print raw packets instead of JSON
f89d23d Added IPv6 support for tcp and udp
3433e83 Added IPv6 support with protocol ICMPv6
66dc90f Added MIT license
2fc379e Added Makefile and startup config file for supervisorctl and systemctl
cc7ae6d Added RDP login attempt rule
1f22cf6 Added README
a73cca6 Added UDP logging
036756f Added UDP rules options and matching logic
296fa0e Added a -o switch to override specific configuration key via CLI. Updated docs & go modules
84520af Added a few comment to config.yml. Added the support for the "enable rotation" option in config file
d1b5e07 Added build dependency in CI release config
1a47f59 Added comment to multistring getopt option. Updated its usage in main.go
e0167da Added comments
c02be3e Added comments in config
81c46f2 Added go module
d6d8f20 Added libpcap install to lint CI job
13a63b7 Added libpcap installation for release CI
fcfc31c Added mkdocs config file and default structure
9fa9558 Added rules.match.protocols option
c792adc Added setcap in the makefile to avoid the need of root privileges. Added protocol filter. Updated the config property for the filters.
ab93372 Added standalone mode and default values for the BPF. Added a switch to specify home directory, config directory, BPF file and inline BPF value
b9fe8d0 Added support for MELODY_CLI environment variable override of CLI args
2db7063 Added support for rule-level match: mode. Added tests for the matching logic flow
8c65fd4 Added support for the missing file code status override
44d9a28 Added tests for UDP
4499b83 Added the default config. Added a few info log messages.
80689a5 Added var/ dirs to git
30651f9 Create log file at launch to allow the watch of the log files even when empty
f6b7116 Disabled directory listing
d8765c8 First commit
5bbdaf3 Fixed / request returned 404 instead of custom status code. Added dedicated user-agent logging.
a746444 Fixed ICMPv6 type and code log data
6ec5232 Fixed UDPLength everywhere and remvoved test prints
9b38aac Fixed error message while parsing config. TimestampNs has been removed and timestamp is now of RFC339Nano format
db01831 Fixed typo
bf7fc8f Fixed typo and added docs/site to .gitignore
98275c4 Fixed typo in router.yml ruleset
34f5192 Got gh pages working
1e11873 ICMPv4/6 now supports payload matching
45e1fb5 Loggers now test the existence of the log dir correctly
b75f435 Merge branch 'master' of https://github.com/bonjourmalware/pinknoise
c42827d Merge branch 'master' of https://github.com/bonjourmalware/pinknoise
dbfa5da Moved test resources
9dd4584 New rule syntax implemented
435fb96 Ready for v1.0.0 release
5e57f08 Reduced the size of the docker image from 600M to 12M
13d6299 Refactored filters into white and blacklist. Port ranges are now supported. Added tests for port ranges.
3b5f7f4 Refactored some code flaws
a42f3a0 Refactored the code with interfaces for easier protocol integration
bb73e74 Removed Statements property from rule
1e10bc3 Removed Statements property from rule
2d4361f Removed built site
e4875ab Removed darwin from release CI
67ab6ca Removed default case in select to prevent 100% CPU usage on one core
f1a1946 Removed i386 arch in release CI
08778c7 Removed icmp rules in rules-enabled
12c8a66 Removed nfqueue attempt
25175c3 Removed obsolete "values" key in nas.yml rule
82ddfd4 Removed obsolete sample configuration files. Removed Homenet configs in favor of inbound and host/net filtering with the bpf
f1db04a Removed test rule
026f488 Renamed "src_ip" match property to "src_ips"
82e26ac Renamed the project as part of the prep work for the future release
e615917 Reverted regression while removing MatchProtocols. Errors and warnings are now sent to stderr when the stdout switch is on
183a3c9 Reworked the rule syntax and the matching engine. The session unique ID is now based on xid
24cc9f8 Small touches
fbb351e Spelling
23cfeac Split events/logdata into its own package to reduce complexity. Refactored tags handling a bit to avoid deduplicating while making log data
b7ef688 Update README.md
021979f Update README.md
a9f4651 Update README.md
d6eb9b5 Update filter.bpf.sample
8f3bd15 Updated .gitignore
d64a537 Updated CI
7dc6682 Updated CI
1a15254 Updated CI
ca61db9 Updated CI
365c3d9 Updated Layers doc
2c537cf Updated Makefile
3187693 Updated Makefile build
f48afb1 Updated README
8418de5 Updated README
e0c2854 Updated README
3b4e465 Updated README
791654b Updated README
88432ee Updated README and docs
9599535 Updated README.md
aeeb40b Updated README.md
4fb5032 Updated README.md
2cea8c4 Updated ci
febfe04 Updated current ruleset to new syntax. Added Additional fields in logs. Added new meta property with author, status, created, modified, description, id fields.
6424c5a Updated cve-2020-14882 rule
675b689 Updated default filter.bpf
2f2c743 Updated docs
2955d61 Updated docs
ce574bb Updated docs
aed3d13 Updated docs and README
8e2a721 Updated go-yaml v3 to overcome the reset of the default config struct when an empty config yaml is given.
83e1237 Updated rules doc
c2fb06d Updated ruleset
f6ecf44 Updated tests for src_ips property

