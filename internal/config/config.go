package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/c2h5oh/datasize"

	"github.com/go-yaml/yaml"
)

const (
	UDPKind     = "udp"
	TCPKind     = "tcp"
	ICMPv4Kind  = "icmpv4"
	ICMPv6Kind  = "icmpv6"
	HTTPKind    = "http"
	DefaultKind = "default"
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
	}
)

type CLI struct {
	PcapFilePath *string
	Stdout       *bool
	Interface    *string
	HomeNet      *[]string
	HomeNet6     *[]string
	Dump         *bool
}

// Config structure which mirrors the yaml file
type Config struct {
	LogFile      string `yaml:"logs.file"`
	LogMaxSize   int    `yaml:"logs.max_size"`
	LogMaxAge       int    `yaml:"logs.max_age"`
	LogCompressRotatedLogs bool   `yaml:"logs.compress_rotated"`

	RulesDir      string `yaml:"rules.dir"`
	BPFFilterFile string `yaml:"listen.bpf.file"`
	BPFFilter     string
	//TODO Accept multiple interfaces ([]string)
	Interface string `yaml:"listen.interface"`
	//EnabledPorts       EnabledPorts
	//RulesVariables     RulesVariables `yaml:"RulesVariables"`
	//EnableBlacklist    bool           `yaml:"EnableBlacklist"`
	//EnableWhitelist    bool           `yaml:"EnableWhitelist"`
	MaxPOSTDataSizeRaw string   `yaml:"logs.http.post.max_size"`
	MaxTCPDataSizeRaw  string   `yaml:"logs.tcp.payload.max_size"`
	MaxUDPDataSizeRaw  string   `yaml:"logs.udp.payload.max_size"`
	MatchProtocols     []string `yaml:"rules.match.protocols"`

	ServerHTTPEnable         bool              `yaml:"server.http.enable"`
	ServerHTTPPort           int               `yaml:"server.http.port"`
	ServerHTTPDir            string            `yaml:"server.http.dir"`
	ServerHTTPResponseStatus int               `yaml:"server.http.response_status"`
	ServerHTTPHeaders        map[string]string `yaml:"server.http.headers"`

	ServerHTTPSEnable         bool              `yaml:"server.https.enable"`
	ServerHTTPSPort           int               `yaml:"server.https.port"`
	ServerHTTPSDir            string            `yaml:"server.https.dir"`
	ServerHTTPSResponseStatus int               `yaml:"server.https.response_status"`
	ServerHTTPSCert           string            `yaml:"server.https.crt"`
	ServerHTTPSKey            string            `yaml:"server.https.key"`
	ServerHTTPSHeaders        map[string]string `yaml:"server.https.headers"`

	HomeNet         []string `yaml:"filter.homenet.ipv4"`
	HomeNet6        []string `yaml:"filter.homenet.ipv6"`
	MaxPOSTDataSize uint64
	MaxTCPDataSize  uint64
	MaxUDPDataSize  uint64
	PcapFile        *os.File
}

func (cfg *Config) Load() {
	var httpByteSize datasize.ByteSize
	var tcpByteSize datasize.ByteSize
	var udpByteSize datasize.ByteSize

	filepath := "config.yml"

	// Default value
	cfg.MaxPOSTDataSizeRaw = "1kb"
	cfg.MaxTCPDataSizeRaw = "1kb"
	cfg.MaxUDPDataSizeRaw = "1kb"

	cfg.LogMaxSize = 200
	cfg.LogCompressRotatedLogs = true
	cfg.LogMaxAge = 15

	cfgData, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Println(fmt.Sprintf("Failed to read config file at [%s]", filepath))
		log.Println(err)
		os.Exit(1)
	}

	if err := httpByteSize.UnmarshalText([]byte(cfg.MaxPOSTDataSizeRaw)); err != nil {
		fmt.Printf("Failed to parse the MaxPOSTDataSize value (%s)\n", cfg.MaxPOSTDataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	if err := tcpByteSize.UnmarshalText([]byte(cfg.MaxTCPDataSizeRaw)); err != nil {
		fmt.Printf("Failed to parse the MaxTCPDataSizeRaw value (%s)\n", cfg.MaxTCPDataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	if err := udpByteSize.UnmarshalText([]byte(cfg.MaxUDPDataSizeRaw)); err != nil {
		fmt.Printf("Failed to parse the MaxUDPDataSizeRaw value (%s)\n", cfg.MaxUDPDataSizeRaw)
		log.Println(err)
		os.Exit(1)
	}

	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		fmt.Printf("Failed to load the config file [%s]\n", filepath)
		log.Println(err)
		os.Exit(1)
	}

	if Cfg.BPFFilterFile != "" {
		bpfData, err := ioutil.ReadFile(Cfg.BPFFilterFile)
		if err != nil {
			log.Println(fmt.Sprintf("Failed to read BPF file at [%s]", Cfg.BPFFilterFile))
			log.Println(err)
			os.Exit(1)
		}

		Cfg.BPFFilter = string(bpfData)
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

	// CLI overrides
	if *Cli.Interface != "" {
		cfg.Interface = *Cli.Interface
	}

	if len(*Cli.HomeNet) > 0 {
		cfg.HomeNet = *Cli.HomeNet
	}

	if len(*Cli.HomeNet6) > 0 {
		cfg.HomeNet6 = *Cli.HomeNet6
	}
}
