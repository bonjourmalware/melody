package config

import (
	"fmt"
	"github.com/c2h5oh/datasize"
	"io/ioutil"
	"os"

	"github.com/go-yaml/yaml"
)

var (
	Cfg = new(Config)
	Cli = new(CLI)
)

type CLI struct {
	PcapFilePath *string
	Stdout       *bool
	Interface    *string
	HomeNet      *[]string
}

// Config structure which mirrors the yaml file
type Config struct {
	LogFile string `yaml:"LogFile"`
	LogMaxSize int `yaml:"LogMaxSize"`
	RulesDir      string `yaml:"RulesDir"`
	BPFFilterFile string `yaml:"BPFFilterFile"`
	BPFFilter     string
	//TODO Accept multiple interfaces ([]string)
	Interface    string `yaml:"Interface"`
	EnabledPorts EnabledPorts
	RulesVariables     RulesVariables `yaml:"RulesVariables"`
	EnableBlacklist    bool           `yaml:"EnableBlacklist"`
	EnableWhitelist    bool           `yaml:"EnableWhitelist"`
	MaxPOSTDataSizeRaw string         `yaml:"MaxPOSTDataSize"`
	MaxTCPDataSizeRaw  string         `yaml:"MaxTCPDataSize"`
	HomeNet            []string       `yaml:"HomeNet"`
	MaxPOSTDataSize    uint64
	MaxTCPDataSize     uint64
	PcapFile           *os.File
}

func (cfg *Config) Load() {
	var httpByteSize datasize.ByteSize
	var tcpByteSize datasize.ByteSize

	filepath := "config.yml"

	// Default value
	cfg.MaxPOSTDataSizeRaw = "1kb"
	cfg.MaxTCPDataSizeRaw = "1kb"

	cfg.LogMaxSize = 200

	cfgData, err := ioutil.ReadFile(filepath)
	if err != nil {
		fmt.Println(fmt.Sprintf("Failed to read config file at [%s]", filepath))
		fmt.Println(err)
		os.Exit(1)
	}

	if err := httpByteSize.UnmarshalText([]byte(cfg.MaxPOSTDataSizeRaw)); err != nil {
		fmt.Printf("Failed to parse the MaxPOSTDataSize value (%s)\n", cfg.MaxPOSTDataSizeRaw)
		fmt.Println(err)
		os.Exit(1)
	}

	if err := tcpByteSize.UnmarshalText([]byte(cfg.MaxTCPDataSizeRaw)); err != nil {
		fmt.Printf("Failed to parse the MaxTCPDataSizeRaw value (%s)\n", cfg.MaxTCPDataSizeRaw)
		fmt.Println(err)
		os.Exit(1)
	}

	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		fmt.Printf("Failed to load the config file [%s]\n", filepath)
		fmt.Println(err)
		os.Exit(1)
	}

	if Cfg.BPFFilterFile != "" {
		bpfData, err := ioutil.ReadFile(Cfg.BPFFilterFile)
		if err != nil {
			fmt.Println(fmt.Sprintf("Failed to read BPF file at [%s]", Cfg.BPFFilterFile))
			fmt.Println(err)
			os.Exit(1)
		}

		Cfg.BPFFilter = string(bpfData)
	}

	cfg.MaxPOSTDataSize = httpByteSize.Bytes()
	cfg.MaxTCPDataSize = tcpByteSize.Bytes()

	if Cli.PcapFilePath != nil && *Cli.PcapFilePath != "" {
		f, err := os.Open(*Cli.PcapFilePath)
		if err != nil {
			fmt.Println(err)
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
}
