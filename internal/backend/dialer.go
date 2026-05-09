package backend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ssh-proxy/internal/config"
	"ssh-proxy/internal/metrics"
	"ssh-proxy/internal/router"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Dialer struct {
	cfg             *config.Config
	logger          *zap.Logger
	metrics         *metrics.Registry
	hostKeyCallback ssh.HostKeyCallback

	mu          sync.Mutex
	signerCache map[string]ssh.Signer
}

func NewDialer(cfg *config.Config, logger *zap.Logger, metrics *metrics.Registry) (*Dialer, error) {
	hostKeyCallback, err := newKnownHostsCallback()
	if err != nil {
		return nil, err
	}

	return &Dialer{
		cfg:             cfg,
		logger:          logger,
		metrics:         metrics,
		hostKeyCallback: hostKeyCallback,
		signerCache:     make(map[string]ssh.Signer),
	}, nil
}

func (d *Dialer) VerifyPassword(ctx context.Context, match *router.MatchResult, password []byte) error {
	authMethods := []ssh.AuthMethod{ssh.Password(string(password))}
	conn, _, _, _, err := d.connect(ctx, match, authMethods)
	if conn != nil {
		_ = conn.Close()
	}
	return err
}

func (d *Dialer) Dial(ctx context.Context, match *router.MatchResult, authMethod string, password []byte) (*Session, error) {
	authMethods, err := d.buildAuthMethods(match, authMethod, password)
	if err != nil {
		return nil, err
	}

	startedAt := time.Now()
	conn, incomingChannels, incomingRequests, failureReason, err := d.connect(ctx, match, authMethods)
	d.metrics.RecordBackendDial(match.BackendName, time.Since(startedAt), failureReason)
	if err != nil {
		return nil, err
	}

	return NewSession(
		conn,
		incomingChannels,
		incomingRequests,
		match,
		authMethod,
		d.cfg.Timeouts.KeepaliveInterval.Duration,
		d.cfg.Timeouts.KeepaliveCountMax,
		d.logger,
		d.metrics,
	), nil
}

func (d *Dialer) buildAuthMethods(match *router.MatchResult, authMethod string, password []byte) ([]ssh.AuthMethod, error) {
	switch authMethod {
	case "password":
		if len(password) == 0 {
			return nil, fmt.Errorf("password auth requires a password secret")
		}
		return []ssh.AuthMethod{ssh.Password(string(password))}, nil
	case "publickey":
		signers, err := d.loadSigners(match)
		if err != nil {
			return nil, err
		}
		if len(signers) == 0 {
			return nil, fmt.Errorf("no backend key is available for backend %q", match.BackendName)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
	default:
		return nil, fmt.Errorf("unsupported auth method %q", authMethod)
	}
}

func (d *Dialer) loadSigners(match *router.MatchResult) ([]ssh.Signer, error) {
	paths := make([]string, 0, 2)
	if match.Backend.PrivateKey != "" {
		paths = append(paths, match.Backend.PrivateKey)
	}
	if d.cfg.ProxyCredentials.PrivateKey != "" && d.cfg.ProxyCredentials.PrivateKey != match.Backend.PrivateKey {
		paths = append(paths, d.cfg.ProxyCredentials.PrivateKey)
	}

	signers := make([]ssh.Signer, 0, len(paths))
	for _, path := range paths {
		signer, err := d.loadSigner(path)
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}

	return signers, nil
}

func (d *Dialer) loadSigner(path string) (ssh.Signer, error) {
	d.mu.Lock()
	signer, ok := d.signerCache[path]
	d.mu.Unlock()
	if ok {
		return signer, nil
	}

	privateKey, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}

	signer, err = ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key %q: %w", path, err)
	}

	d.mu.Lock()
	d.signerCache[path] = signer
	d.mu.Unlock()

	return signer, nil
}

func (d *Dialer) connect(ctx context.Context, match *router.MatchResult, authMethods []ssh.AuthMethod) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, string, error) {
	backendCtx, cancel := context.WithTimeout(ctx, d.cfg.Timeouts.BackendConnect.Duration)
	defer cancel()

	backendAddr := match.Backend.Address()
	netConn, err := (&net.Dialer{}).DialContext(backendCtx, "tcp", backendAddr)
	if err != nil {
		return nil, nil, nil, classifyDialError(err), fmt.Errorf("dial backend %s: %w", backendAddr, err)
	}

	deadline := time.Now().Add(d.cfg.Timeouts.BackendHandshake.Duration)
	if ctxDeadline, ok := backendCtx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := netConn.SetDeadline(deadline); err != nil {
		_ = netConn.Close()
		return nil, nil, nil, "handshake", fmt.Errorf("set backend deadline: %w", err)
	}

	conn, incomingChannels, incomingRequests, err := ssh.NewClientConn(netConn, backendAddr, &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges:         append([]string(nil), d.cfg.Proxy.Algorithms.KEX...),
			Ciphers:              append([]string(nil), d.cfg.Proxy.Algorithms.Ciphers...),
			MACs:                 append([]string(nil), d.cfg.Proxy.Algorithms.MACs...),
			ChannelWindowSize:    uint32(d.cfg.SFTP.WindowSize),
			ChannelMaxPacketSize: uint32(d.cfg.SFTP.MaxPacketSize),
		},
		User:              match.BackendUsername,
		Auth:              authMethods,
		HostKeyCallback:   d.hostKeyCallback,
		HostKeyAlgorithms: append([]string(nil), d.cfg.Proxy.Algorithms.HostKeyAlgos...),
		Timeout:           d.cfg.Timeouts.BackendConnect.Duration,
	})
	if err != nil {
		_ = netConn.Close()
		return nil, nil, nil, classifyDialError(err), fmt.Errorf("ssh client handshake for backend %s: %w", backendAddr, err)
	}

	if err := netConn.SetDeadline(time.Time{}); err != nil {
		d.logger.Warn("clear backend deadline failed", zap.String("backend", match.BackendName), zap.Error(err))
	}

	return conn, incomingChannels, incomingRequests, "", nil
}

func classifyDialError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}

	errText := err.Error()
	switch {
	case strings.Contains(errText, "unable to authenticate"):
		return "auth"
	case strings.Contains(errText, "handshake failed"):
		return "handshake"
	default:
		return "dial"
	}
}

func newKnownHostsCallback() (ssh.HostKeyCallback, error) {
	paths := existingKnownHostsPaths(defaultKnownHostsPaths())
	if len(paths) == 0 {
		return nil, fmt.Errorf("no known_hosts file found; configure /etc/ssh-proxy/known_hosts, /etc/ssh/ssh_known_hosts, or ~/.ssh/known_hosts")
	}

	callback, err := knownhosts.New(paths...)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return callback, nil
}

func defaultKnownHostsPaths() []string {
	paths := []string{
		"/etc/ssh-proxy/known_hosts",
		"/etc/ssh/ssh_known_hosts",
		"/etc/ssh/ssh_known_hosts2",
	}

	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".ssh", "known_hosts"),
			filepath.Join(home, ".ssh", "known_hosts2"),
		)
	}

	return paths
}

func existingKnownHostsPaths(paths []string) []string {
	existing := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			existing = append(existing, path)
		}
	}
	return existing
}
