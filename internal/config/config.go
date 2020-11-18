package config

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/bonjourmalware/melody/internal/clihelper"

	"github.com/c2h5oh/datasize"

	"gopkg.in/yaml.v3"
)

const (
	// UDPKind is the constant used to define a Kind as UDP
	UDPKind = "udp"

	// TCPKind is the constant used to define a Kind as TCP
	TCPKind = "tcp"

	// ICMPv4Kind is the constant used to define a Kind as ICMPv4
	ICMPv4Kind = "icmpv4"

	// ICMPv6Kind is the constant used to define a Kind as ICMPv6
	ICMPv6Kind = "icmpv6"

	// HTTPKind is the constant used to define a Kind as HTTP
	HTTPKind = "http"

	// HTTPSKind is the constant used to define a Kind as HTTPS
	HTTPSKind = "https"

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
logs.icmpv4.payload.max_size: "10KB"
logs.icmpv6.payload.max_size: "10KB"

rules.dir: "rules/rules-enabled"
rules.match.protocols: ["all"]

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
	// Cfg exposes the global config
	Cfg = new(Config)
	// Cli exposes the CLI config
	Cli = new(CLI)

	// SupportedProtocols lists the network protocols supported by Melody
	SupportedProtocols = []string{
		TCPKind,
		UDPKind,
		ICMPv4Kind,
		ICMPv6Kind,
		HTTPKind,
		HTTPSKind,
	}
)

// CLI describes the available CLI config keys
type CLI struct {
	PcapFilePath   *string
	BPF            *string
	Stdout         *bool
	Interface      *string
	Dump           *bool
	ConfigFilePath *string
	ConfigDirPath  *string
	BPFFilePath    *string
	HomeDirPath    *string
	FreeConfig     clihelper.MultiString
}

// Config structure which mirrors the yaml file
type Config struct {
	ConfigFilePath string
	ConfigDirPath  string
	BPFFilePath    string
	HomeDirPath    string
	LogsDir        string `yaml:"logs.dir"`

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

	Interface            string   `yaml:"listen.interface"`
	MaxPOSTDataSizeRaw   string   `yaml:"logs.http.post.max_size"`
	MaxTCPDataSizeRaw    string   `yaml:"logs.tcp.payload.max_size"`
	MaxUDPDataSizeRaw    string   `yaml:"logs.udp.payload.max_size"`
	MaxICMPv4DataSizeRaw string   `yaml:"logs.icmpv4.payload.max_size"`
	MaxICMPv6DataSizeRaw string   `yaml:"logs.icmpv6.payload.max_size"`
	MatchProtocols       []string `yaml:"rules.match.protocols"`

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

	MaxPOSTDataSize   uint64
	MaxTCPDataSize    uint64
	MaxUDPDataSize    uint64
	MaxICMPv4DataSize uint64
	MaxICMPv6DataSize uint64
	PcapFile          *os.File
}

// Load set the default values and parse the user's config
func (cfg *Config) Load() {
	if err := yaml.Unmarshal([]byte(defaultConfig), cfg); err != nil {
		log.Println("Failed to load default config")
		log.Println(err)
		os.Exit(1)
	}

	if err := cfg.parseConfigAt(nil); err != nil {
		log.Println("Failed to parse default config")
		log.Println(err)
		os.Exit(1)
	}

	cfg.ConfigDirPath = "."
	cfg.HomeDirPath = "."
	cfg.ConfigFilePath = "config.yml"
	cfg.BPFFilePath = "filter.bpf"

	cfg.loadCLIConfigEnv()

	if err := cfg.parseConfig(); err != nil {
		log.Println("Failed to read config file")
		log.Println(err)
		log.Println("Fallback on default config values")
	}

	if err := cfg.parseBPF(); err != nil {
		log.Println("Failed to read BPF file")
		log.Println(err)
		log.Printf("Fallback on default filter ('%s')\n", cfg.BPF)
	}

	cfg.loadCLIOverrides()
}

func rawDatasizeToBytes(raw string) (uint64, error) {
	var byteSize datasize.ByteSize
	if err := byteSize.UnmarshalText([]byte(raw)); err != nil {
		return 0, err
	}

	return byteSize.Bytes(), nil
}

func rawDatasizeToMegabytes(raw string) (int, error) {
	var byteSize datasize.ByteSize
	if err := byteSize.UnmarshalText([]byte(raw)); err != nil {
		return 0, err
	}

	return int(byteSize.MBytes()), nil
}

func (cfg *Config) parseConfig() error {
	var err error
	var ok bool
	homeDirConfigPath := filepath.Join(Cfg.ConfigDirPath, Cfg.ConfigFilePath)

	if ok, err = exists(homeDirConfigPath); ok {
		err := cfg.parseConfigAt(&Cfg.ConfigFilePath)
		if err != nil {
			return err
		}
	}

	return err
}

func (cfg *Config) parseBPF() error {
	var err error
	var ok bool
	homeDirBPFPath := filepath.Join(Cfg.ConfigDirPath, Cfg.BPFFilePath)

	// Default BPF filter
	cfg.BPF = "inbound and not net 127.0.0.0/24"

	if ok, err = exists(homeDirBPFPath); ok {
		err := cfg.parseBPFAt(homeDirBPFPath)
		if err != nil {
			return err
		}
	}

	return err
}

func (cfg *Config) parseBPFAt(filepath string) error {
	bpfData, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	Cfg.BPF = string(bpfData)
	return nil
}

func (cfg *Config) parseConfigAt(filepath *string) error {
	var err error

	if filepath != nil {
		cfgData, err := ioutil.ReadFile(*filepath)
		if err != nil {
			return err
		}

		if err := yaml.Unmarshal(cfgData, cfg); err != nil {
			return err
		}
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

	cfg.LogsSensorMaxSize, err = rawDatasizeToMegabytes(cfg.LogsSensorMaxSizeRaw)
	if err != nil {
		log.Printf("Failed to parse the logs.sensor.max_size value (%s)\n", cfg.LogsSensorMaxSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	cfg.LogsErrorsMaxSize, err = rawDatasizeToMegabytes(cfg.LogsErrorsMaxSizeRaw)
	if err != nil {
		log.Printf("Failed to parse the logs.errors.max_size value (%s)\n", cfg.LogsErrorsMaxSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	cfg.MaxPOSTDataSize, err = rawDatasizeToBytes(cfg.MaxPOSTDataSizeRaw)
	if err != nil {
		log.Printf("Failed to parse the logs.http.post.max_size value (%s)\n", cfg.MaxPOSTDataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	cfg.MaxTCPDataSize, err = rawDatasizeToBytes(cfg.MaxTCPDataSizeRaw)
	if err != nil {
		log.Printf("Failed to parse the logs.tcp.post.max_size value (%s)\n", cfg.MaxTCPDataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	cfg.MaxUDPDataSize, err = rawDatasizeToBytes(cfg.MaxUDPDataSizeRaw)
	if err != nil {
		log.Printf("Failed to parse the logs.udp.post.max_size value (%s)\n", cfg.MaxUDPDataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	cfg.MaxICMPv4DataSize, err = rawDatasizeToBytes(cfg.MaxICMPv4DataSizeRaw)
	if err != nil {
		log.Printf("Failed to parse the logs.icmpv4.post.max_size value (%s)\n", cfg.MaxICMPv4DataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	cfg.MaxICMPv6DataSize, err = rawDatasizeToBytes(cfg.MaxICMPv6DataSizeRaw)
	if err != nil {
		log.Printf("Failed to parse the logs.icmpv6.post.max_size value (%s)\n", cfg.MaxICMPv6DataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

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

	return nil
}

func (cfg *Config) loadCLIConfigEnv() {
	if *Cli.HomeDirPath != "" {
		cfg.HomeDirPath = *Cli.HomeDirPath
	}

	if *Cli.ConfigDirPath != "" {
		cfg.ConfigDirPath = *Cli.ConfigDirPath
	}

	if *Cli.ConfigFilePath != "" {
		cfg.ConfigFilePath = *Cli.ConfigFilePath
	}

	if *Cli.BPFFilePath != "" {
		cfg.BPFFilePath = *Cli.BPFFilePath
	}
}

func (cfg *Config) loadCLIOverrides() {
	if *Cli.Interface != "" {
		cfg.Interface = *Cli.Interface
	}

	if *Cli.BPF != "" {
		cfg.BPF = *Cli.BPF
	}

	for _, val := range Cli.FreeConfig.Array() {
		if err := yaml.Unmarshal([]byte(val), cfg); err != nil {
			log.Printf("Failed to load free config option : %s\n", val)
			log.Println(err)
		}
	}
}
