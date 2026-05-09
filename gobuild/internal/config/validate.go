package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var (
	allowedKEX = map[string]struct{}{
		"curve25519-sha256":             {},
		"ecdh-sha2-nistp521":            {},
		"ecdh-sha2-nistp384":            {},
		"ecdh-sha2-nistp256":            {},
		"diffie-hellman-group14-sha256": {},
		"diffie-hellman-group14-sha1":   {},
	}
	allowedCiphers = map[string]struct{}{
		"chacha20-poly1305@openssh.com": {},
		"aes256-gcm@openssh.com":        {},
		"aes128-gcm@openssh.com":        {},
		"aes256-ctr":                    {},
		"aes192-ctr":                    {},
		"aes128-ctr":                    {},
	}
	allowedMACs = map[string]struct{}{
		"hmac-sha2-512-etm@openssh.com": {},
		"hmac-sha2-256-etm@openssh.com": {},
		"hmac-sha2-512":                 {},
		"hmac-sha2-256":                 {},
		"hmac-sha1":                     {},
	}
	allowedHostKeyAlgos = map[string]struct{}{
		"ssh-ed25519":         {},
		"ecdsa-sha2-nistp521": {},
		"ecdsa-sha2-nistp384": {},
		"ecdsa-sha2-nistp256": {},
		"rsa-sha2-512":        {},
		"rsa-sha2-256":        {},
		"ssh-rsa":             {},
	}
	allowedLogLevels = map[string]struct{}{
		"debug": {},
		"info":  {},
		"warn":  {},
		"error": {},
	}
	allowedLogFormats = map[string]struct{}{
		"json": {},
		"text": {},
	}
)

func (cfg *Config) Validate() error {
	if cfg.Proxy.Listen == "" {
		return fmt.Errorf("proxy.listen is required")
	}
	if len(cfg.Proxy.HostKeys) == 0 {
		return fmt.Errorf("proxy.host_keys must contain at least one path")
	}
	if err := validateAlgorithms(cfg.Proxy.Algorithms); err != nil {
		return err
	}
	if cfg.Timeouts.BackendConnect.Duration <= 0 {
		return fmt.Errorf("timeouts.backend_connect must be positive")
	}
	if cfg.Timeouts.BackendHandshake.Duration <= 0 {
		return fmt.Errorf("timeouts.backend_handshake must be positive")
	}
	if cfg.Timeouts.KeepaliveInterval.Duration <= 0 {
		return fmt.Errorf("timeouts.keepalive_interval must be positive")
	}
	if cfg.Timeouts.KeepaliveCountMax <= 0 {
		return fmt.Errorf("timeouts.keepalive_count_max must be positive")
	}
	if cfg.SFTP.WindowSize <= 0 {
		return fmt.Errorf("sftp.window_size must be positive")
	}
	if cfg.SFTP.MaxPacketSize <= 0 {
		return fmt.Errorf("sftp.max_packet_size must be positive")
	}
	if cfg.SFTP.MaxConcurrentRequests <= 0 {
		return fmt.Errorf("sftp.max_concurrent_requests must be positive")
	}
	if len(cfg.Backends) == 0 {
		return fmt.Errorf("backends must define at least one backend")
	}
	for _, keyPath := range cfg.Proxy.HostKeys {
		if err := validateKeyPath(keyPath); err != nil {
			return fmt.Errorf("validate proxy host key %q: %w", keyPath, err)
		}
	}
	if cfg.ProxyCredentials.PrivateKey != "" {
		if err := validateKeyPath(cfg.ProxyCredentials.PrivateKey); err != nil {
			return fmt.Errorf("validate proxy_credentials.private_key: %w", err)
		}
	}
	for name, backend := range cfg.Backends {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("backend name cannot be empty")
		}
		if backend.Host == "" {
			return fmt.Errorf("backends.%s.host is required", name)
		}
		if backend.Port <= 0 || backend.Port > 65535 {
			return fmt.Errorf("backends.%s.port must be between 1 and 65535", name)
		}
		if backend.PrivateKey != "" {
			if err := validateKeyPath(backend.PrivateKey); err != nil {
				return fmt.Errorf("validate backends.%s.private_key: %w", name, err)
			}
		}
	}
	if len(cfg.Rules) == 0 {
		return fmt.Errorf("rules must define at least one routing rule")
	}
	for idx, rule := range cfg.Rules {
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("rules[%d].name is required", idx)
		}
		if strings.TrimSpace(rule.Match) == "" {
			return fmt.Errorf("rules[%d].match is required", idx)
		}
		if _, err := regexp.Compile(rule.Match); err != nil {
			return fmt.Errorf("rules[%d].match is invalid regex: %w", idx, err)
		}
		if _, ok := cfg.Backends[rule.Backend]; !ok {
			return fmt.Errorf("rules[%d].backend references unknown backend %q", idx, rule.Backend)
		}
		if strings.TrimSpace(rule.BackendUsername) == "" {
			return fmt.Errorf("rules[%d].backend_username is required", idx)
		}
	}
	if cfg.Metrics.Enabled {
		if cfg.Metrics.Listen == "" {
			return fmt.Errorf("metrics.listen is required when metrics.enabled is true")
		}
		if cfg.Metrics.Path == "" {
			return fmt.Errorf("metrics.path is required when metrics.enabled is true")
		}
	}
	if _, ok := allowedLogLevels[cfg.Logging.Level]; !ok {
		return fmt.Errorf("logging.level %q is not supported", cfg.Logging.Level)
	}
	if _, ok := allowedLogFormats[cfg.Logging.Format]; !ok {
		return fmt.Errorf("logging.format %q is not supported", cfg.Logging.Format)
	}
	if strings.TrimSpace(cfg.Logging.Output) == "" {
		return fmt.Errorf("logging.output is required")
	}

	return nil
}

func validateAlgorithms(algorithms AlgorithmsConfig) error {
	if err := validateAllowedList("proxy.algorithms.kex", algorithms.KEX, allowedKEX); err != nil {
		return err
	}
	if err := validateAllowedList("proxy.algorithms.ciphers", algorithms.Ciphers, allowedCiphers); err != nil {
		return err
	}
	if err := validateAllowedList("proxy.algorithms.macs", algorithms.MACs, allowedMACs); err != nil {
		return err
	}
	if err := validateAllowedList("proxy.algorithms.host_key_algos", algorithms.HostKeyAlgos, allowedHostKeyAlgos); err != nil {
		return err
	}
	return nil
}

func validateAllowedList(field string, values []string, allowed map[string]struct{}) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must contain at least one entry", field)
	}
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			return fmt.Errorf("%s contains unsupported value %q", field, value)
		}
	}
	return nil
}

func validateKeyPath(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}

	cleanPath := filepath.Clean(path)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", cleanPath)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not be accessible by group or others", cleanPath)
	}
	return nil
}
