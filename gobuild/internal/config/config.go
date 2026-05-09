package config

import (
	"fmt"
	"os"
	"time"

	proxysftp "ssh-proxy/internal/sftp"

	"gopkg.in/yaml.v3"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}

	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", node.Value, err)
	}

	d.Duration = parsed
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

type Config struct {
	Proxy            ProxyConfig              `yaml:"proxy"`
	ProxyCredentials ProxyCredentialsConfig   `yaml:"proxy_credentials"`
	SFTP             SFTPConfig               `yaml:"sftp"`
	Timeouts         TimeoutsConfig           `yaml:"timeouts"`
	Backends         map[string]BackendConfig `yaml:"backends"`
	Rules            []RuleConfig             `yaml:"rules"`
	Metrics          MetricsConfig            `yaml:"metrics"`
	Logging          LoggingConfig            `yaml:"logging"`
}

type ProxyConfig struct {
	Listen     string           `yaml:"listen"`
	HostKeys   []string         `yaml:"host_keys"`
	Algorithms AlgorithmsConfig `yaml:"algorithms"`
}

type AlgorithmsConfig struct {
	KEX          []string `yaml:"kex"`
	Ciphers      []string `yaml:"ciphers"`
	MACs         []string `yaml:"macs"`
	HostKeyAlgos []string `yaml:"host_key_algos"`
}

type ProxyCredentialsConfig struct {
	PrivateKey string `yaml:"private_key"`
}

type SFTPConfig struct {
	WindowSize            int `yaml:"window_size"`
	MaxPacketSize         int `yaml:"max_packet_size"`
	MaxConcurrentRequests int `yaml:"max_concurrent_requests"`
}

type TimeoutsConfig struct {
	BackendConnect    Duration `yaml:"backend_connect"`
	BackendHandshake  Duration `yaml:"backend_handshake"`
	KeepaliveInterval Duration `yaml:"keepalive_interval"`
	KeepaliveCountMax int      `yaml:"keepalive_count_max"`
}

type BackendConfig struct {
	Name               string `yaml:"-"`
	Host               string `yaml:"host"`
	Port               int    `yaml:"port"`
	PrivateKey         string `yaml:"private_key"`
	FallbackToPassword bool   `yaml:"fallback_to_password"`
}

func (b BackendConfig) Address() string {
	return fmt.Sprintf("%s:%d", b.Host, b.Port)
}

type RuleConfig struct {
	Name            string `yaml:"name"`
	Match           string `yaml:"match"`
	Backend         string `yaml:"backend"`
	BackendUsername string `yaml:"backend_username"`
	RequirePubkey   bool   `yaml:"require_pubkey"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Path    string `yaml:"path"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}

	cfg.applyDefaults()
	for name, backend := range cfg.Backends {
		backend.Name = name
		cfg.Backends[name] = backend
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (cfg *Config) applyDefaults() {
	if cfg.Proxy.Listen == "" {
		cfg.Proxy.Listen = "0.0.0.0:22"
	}

	applyDefaultAlgorithms(&cfg.Proxy.Algorithms)

	if cfg.SFTP.WindowSize == 0 {
		cfg.SFTP.WindowSize = proxysftp.ChannelWindowSize
	}
	if cfg.SFTP.MaxPacketSize == 0 {
		cfg.SFTP.MaxPacketSize = proxysftp.ChannelMaxPacketSize
	}
	if cfg.SFTP.MaxConcurrentRequests == 0 {
		cfg.SFTP.MaxConcurrentRequests = proxysftp.SFTPMaxConcurrentRequests
	}

	if cfg.Timeouts.BackendConnect.Duration == 0 {
		cfg.Timeouts.BackendConnect = Duration{Duration: 10 * time.Second}
	}
	if cfg.Timeouts.BackendHandshake.Duration == 0 {
		cfg.Timeouts.BackendHandshake = Duration{Duration: 15 * time.Second}
	}
	if cfg.Timeouts.KeepaliveInterval.Duration == 0 {
		cfg.Timeouts.KeepaliveInterval = Duration{Duration: 30 * time.Second}
	}
	if cfg.Timeouts.KeepaliveCountMax == 0 {
		cfg.Timeouts.KeepaliveCountMax = 3
	}

	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
	if cfg.Backends == nil {
		cfg.Backends = make(map[string]BackendConfig)
	}
}

func applyDefaultAlgorithms(algorithms *AlgorithmsConfig) {
	if len(algorithms.KEX) == 0 {
		algorithms.KEX = []string{
			"curve25519-sha256",
			"ecdh-sha2-nistp521",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp256",
			"diffie-hellman-group14-sha256",
			"diffie-hellman-group14-sha1",
		}
	}
	if len(algorithms.Ciphers) == 0 {
		algorithms.Ciphers = []string{
			"chacha20-poly1305@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-ctr",
			"aes192-ctr",
			"aes128-ctr",
		}
	}
	if len(algorithms.MACs) == 0 {
		algorithms.MACs = []string{
			"hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512",
			"hmac-sha2-256",
			"hmac-sha1",
		}
	}
	if len(algorithms.HostKeyAlgos) == 0 {
		algorithms.HostKeyAlgos = []string{
			"ssh-ed25519",
			"ecdsa-sha2-nistp521",
			"ecdsa-sha2-nistp384",
			"ecdsa-sha2-nistp256",
			"rsa-sha2-512",
			"rsa-sha2-256",
			"ssh-rsa",
		}
	}
}
