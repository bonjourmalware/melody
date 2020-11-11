package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/c2h5oh/datasize"

	"gopkg.in/yaml.v3"
)

const (
	UDPKind    = "udp"
	TCPKind    = "tcp"
	ICMPv4Kind = "icmpv4"
	ICMPv6Kind = "icmpv6"
	HTTPKind   = "http"
	HTTPSKind  = "https"

	defaultConfig = `---
logs.dir: "logs/"

logs.sensor.file: melody.ndjson
logs.sensor.rotation.max_size: 1G
logs.sensor.rotation.max_age: 30 # days
logs.sensor.rotation.enable: true
logs.sensor.rotation.compress: true

logs.errors.file: melody_err.log
logs.errors.rotation.max_size: 1G
logs.errors.rotation.max_age: 30 # days
logs.errors.rotation.enable: true
logs.errors.rotation.compress: true

logs.http.post.max_size: "10KB"
logs.tcp.payload.max_size: "10KB"
logs.udp.payload.max_size: "10KB"

rules.dir: "rules/rules-enabled"

listen.interface: "lo"
filters.bpf.file: "filter.bpf"

filters.ipv4.proto: []
filters.ipv6.proto: []

server.http.enable: true
server.http.port: 10080
server.http.dir: "var/http/serve"
server.http.response.missing_status_code: 200
server.http.response.headers:
      Server: "Apache"

server.https.enable: true
server.https.port: 10443
server.https.dir: "var/https/serve"
server.https.crt: "var/https/certs/cert.pem"
server.https.key: "var/https/certs/key.pem"
server.https.response.missing_status_code: 200
server.https.response.headers:
      Server: "Apache"
`
)

var (
	Cfg = new(Config)
	Cli = new(CLI)

	SupportedProtocols = []string{
		TCPKind,
		UDPKind,
		ICMPv4Kind,
		ICMPv6Kind,
		HTTPKind,
		HTTPSKind,
	}
)

type CLI struct {
	PcapFilePath *string
	BPF          *string
	Stdout       *bool
	Interface    *string
	Dump         *bool
}

// Config structure which mirrors the yaml file
type Config struct {
	LogsDir string `yaml:"logs.dir"`

	LogsSensorFile                string `yaml:"logs.sensor.file"`
	LogsSensorMaxSizeRaw          string `yaml:"logs.sensor.rotation.max_size"`
	LogsSensorMaxSize             int
	LogsSensorMaxAge              int  `yaml:"logs.sensor.rotation.max_age"`
	LogsSensorCompressRotatedLogs bool `yaml:"logs.sensor.rotation.compress"`
	LogSensorEnableRotation       bool `yaml:"logs.sensor.rotation.enable"`

	LogsErrorsFile                string `yaml:"logs.errors.file"`
	LogsErrorsMaxSizeRaw          string `yaml:"logs.errors.rotation.max_size"`
	LogsErrorsMaxSize             int
	LogsErrorsMaxAge              int  `yaml:"logs.errors.rotation.max_age"`
	LogsErrorsCompressRotatedLogs bool `yaml:"logs.errors.rotation.compress"`
	LogErrorsEnableRotation       bool `yaml:"logs.errors.rotation.enable"`

	RulesDir string `yaml:"rules.dir"`
	BPFFile  string `yaml:"filters.bpf.file"`
	BPF      string
	//TODO Accept multiple interfaces ([]string)
	Interface          string   `yaml:"listen.interface"`
	MaxPOSTDataSizeRaw string   `yaml:"logs.http.post.max_size"`
	MaxTCPDataSizeRaw  string   `yaml:"logs.tcp.payload.max_size"`
	MaxUDPDataSizeRaw  string   `yaml:"logs.udp.payload.max_size"`
	MatchProtocols     []string `yaml:"rules.match.protocols"`

	ServerHTTPEnable                bool              `yaml:"server.http.enable"`
	ServerHTTPPort                  int               `yaml:"server.http.port"`
	ServerHTTPDir                   string            `yaml:"server.http.dir"`
	ServerHTTPMissingResponseStatus int               `yaml:"server.http.response.missing_status_code"`
	ServerHTTPHeaders               map[string]string `yaml:"server.http.response.headers"`

	ServerHTTPSEnable                bool              `yaml:"server.https.enable"`
	ServerHTTPSPort                  int               `yaml:"server.https.port"`
	ServerHTTPSDir                   string            `yaml:"server.https.dir"`
	ServerHTTPSMissingResponseStatus int               `yaml:"server.https.response.missing_status_code"`
	ServerHTTPSCert                  string            `yaml:"server.https.crt"`
	ServerHTTPSKey                   string            `yaml:"server.https.key"`
	ServerHTTPSHeaders               map[string]string `yaml:"server.https.response.headers"`

	RawDiscardProto4 []string `yaml:"filters.ipv4.proto"`
	RawDiscardProto6 []string `yaml:"filters.ipv6.proto"`

	DiscardProto4 map[string]interface{}
	DiscardProto6 map[string]interface{}

	MaxPOSTDataSize uint64
	MaxTCPDataSize  uint64
	MaxUDPDataSize  uint64
	PcapFile        *os.File
}

func (cfg *Config) Load() {
	var httpByteSize datasize.ByteSize
	var tcpByteSize datasize.ByteSize
	var udpByteSize datasize.ByteSize
	var sensorFileByteSize datasize.ByteSize
	var errorsFileByteSize datasize.ByteSize

	if err := yaml.Unmarshal([]byte(defaultConfig), cfg); err != nil {
		log.Println("Failed to load default config")
		log.Println(err)
		os.Exit(1)
	}

	filepath := "config.yml"

	cfgData, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Println(fmt.Sprintf("Failed to read config file at [%s]", filepath))
		log.Println(err)
		os.Exit(1)
	}

	if err := yaml.Unmarshal(cfgData, cfg); err != nil {
		log.Printf("Failed to load the config file [%s]\n", filepath)
		log.Println(err)
		os.Exit(1)
	}

	if err := httpByteSize.UnmarshalText([]byte(cfg.MaxPOSTDataSizeRaw)); err != nil {
		log.Printf("Failed to parse the logs.http.post.max_size value (%s)\n", cfg.MaxPOSTDataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	if err := tcpByteSize.UnmarshalText([]byte(cfg.MaxTCPDataSizeRaw)); err != nil {
		log.Printf("Failed to parse the logs.tcp.payload.max_size value (%s)\n", cfg.MaxTCPDataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	if err := udpByteSize.UnmarshalText([]byte(cfg.MaxUDPDataSizeRaw)); err != nil {
		log.Printf("Failed to parse the logs.udp.payload.max_size value (%s)\n", cfg.MaxUDPDataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	if err := sensorFileByteSize.UnmarshalText([]byte(cfg.LogsSensorMaxSizeRaw)); err != nil {
		log.Printf("Failed to parse the logs.sensor.max_size value (%s)\n", cfg.LogsSensorMaxSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	if err := errorsFileByteSize.UnmarshalText([]byte(cfg.LogsErrorsMaxSizeRaw)); err != nil {
		log.Printf("Failed to parse the logs.errors.max_size value (%s)\n", cfg.LogsErrorsMaxSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	if Cfg.BPFFile != "" {
		bpfData, err := ioutil.ReadFile(Cfg.BPFFile)
		if err != nil {
			log.Printf("Failed to read BPF file at [%s]\n", Cfg.BPFFile)
			log.Println(err)
			os.Exit(1)
		}

		Cfg.BPF = string(bpfData)
	}

	if len(Cfg.MatchProtocols) == 0 {
		Cfg.MatchProtocols = SupportedProtocols
	} else {
		for _, proto := range Cfg.MatchProtocols {
			if proto == "all" {
				Cfg.MatchProtocols = SupportedProtocols
				break
			}
		}
	}

	cfg.LogsSensorMaxSize = int(sensorFileByteSize.MBytes())
	cfg.LogsErrorsMaxSize = int(errorsFileByteSize.MBytes())
	cfg.MaxPOSTDataSize = httpByteSize.Bytes()
	cfg.MaxTCPDataSize = tcpByteSize.Bytes()
	cfg.MaxUDPDataSize = udpByteSize.Bytes()

	if Cli.PcapFilePath != nil && *Cli.PcapFilePath != "" {
		f, err := os.Open(*Cli.PcapFilePath)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		cfg.PcapFile = f
	}

	Cfg.DiscardProto4 = make(map[string]interface{})
	for _, proto := range Cfg.RawDiscardProto4 {
		if proto == "icmp" { // Allow for 'icmp' as an alias for icmpv4
			Cfg.DiscardProto4["icmpv4"] = struct{}{}
		}
		Cfg.DiscardProto4[proto] = struct{}{}
	}

	Cfg.DiscardProto6 = make(map[string]interface{})
	for _, proto := range Cfg.RawDiscardProto6 {
		if proto == "icmp" { // Allow for 'icmp' as an alias for icmpv6
			Cfg.DiscardProto6["icmpv6"] = struct{}{}
		}
		Cfg.DiscardProto6[proto] = struct{}{}
	}

	if http.StatusText(Cfg.ServerHTTPMissingResponseStatus) == "" {
		log.Printf("'%d' is not a valid HTTP code status\n", Cfg.ServerHTTPMissingResponseStatus)
		os.Exit(1)
	}

	if http.StatusText(Cfg.ServerHTTPSMissingResponseStatus) == "" {
		log.Printf("'%d' is not a valid HTTP code status\n", Cfg.ServerHTTPSMissingResponseStatus)
		os.Exit(1)
	}

	// CLI overrides
	if *Cli.Interface != "" {
		cfg.Interface = *Cli.Interface
	}

	if *Cli.BPF != "" {
		cfg.BPF = *Cli.BPF
	}
}
