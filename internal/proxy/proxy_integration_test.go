package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"ssh-proxy/internal/config"
	"ssh-proxy/internal/metrics"
	"ssh-proxy/internal/proxy"
	proxysftp "ssh-proxy/internal/sftp"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestProxyPasswordAuthSessionAndGlobalRequest(t *testing.T) {
	backend := startBackendSSHServer(t, backendServerOptions{
		expectedUser:     "alice",
		expectedPassword: "secret",
	})
	defer backend.stop()

	configureKnownHostsHome(t, backend.addr, backend.hostSigner.PublicKey())

	_, proxyHostKeyPath := generateSignerAndWritePrivateKeyFile(t, t.TempDir(), "proxy_host")
	cfg := newTestConfig(t, proxyHostKeyPath, "", backend.addr, "", "nas", []config.RuleConfig{
		{
			Name:            "nas-wildcard",
			Match:           "^(.*)-nas$",
			Backend:         "nas",
			BackendUsername: "$1",
		},
	})

	proxyAddr, stopProxy := startProxyServer(t, cfg)
	defer stopProxy()

	client := dialSSHClient(t, proxyAddr, "alice-nas", ssh.Password("secret"))
	defer client.Close()

	ok, payload, err := client.SendRequest("unit-test-global", true, []byte("ping"))
	if err != nil {
		t.Fatalf("send global request: %v", err)
	}
	if !ok {
		t.Fatal("expected global request reply to be accepted")
	}
	if string(payload) != "global-ok" {
		t.Fatalf("unexpected global request payload: got %q want %q", string(payload), "global-ok")
	}

	channel, incomingRequests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session channel: %v", err)
	}
	defer channel.Close()
	go ssh.DiscardRequests(incomingRequests)

	ok, err = channel.SendRequest("unit-test-request", true, []byte("channel-check"))
	if err != nil {
		t.Fatalf("send channel request: %v", err)
	}
	if !ok {
		t.Fatal("expected channel request to be accepted")
	}

	message := []byte("password-path")
	if _, err := channel.Write(message); err != nil {
		t.Fatalf("write session payload: %v", err)
	}
	if err := channel.CloseWrite(); err != nil {
		t.Fatalf("close session writer: %v", err)
	}

	echoed, err := io.ReadAll(channel)
	if err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if !bytes.Equal(echoed, message) {
		t.Fatalf("unexpected echoed payload: got %q want %q", string(echoed), string(message))
	}
}

func TestProxyPublicKeyAuthUsesBackendKey(t *testing.T) {
	workDir := t.TempDir()
	backendAuthSigner, backendAuthKeyPath := generateSignerAndWritePrivateKeyFile(t, workDir, "backend_auth")
	backend := startBackendSSHServer(t, backendServerOptions{
		expectedUser:      "user1",
		expectedPublicKey: backendAuthSigner.PublicKey(),
	})
	defer backend.stop()

	configureKnownHostsHome(t, backend.addr, backend.hostSigner.PublicKey())

	_, proxyHostKeyPath := generateSignerAndWritePrivateKeyFile(t, workDir, "proxy_host")

	cfg := newTestConfig(t, proxyHostKeyPath, "", backend.addr, backendAuthKeyPath, "vm", []config.RuleConfig{
		{
			Name:            "user1-vm-keyonly",
			Match:           "^user1-vm$",
			Backend:         "vm",
			BackendUsername: "user1",
			RequirePubkey:   true,
		},
	})

	proxyAddr, stopProxy := startProxyServer(t, cfg)
	defer stopProxy()

	if _, err := ssh.Dial("tcp", proxyAddr, &ssh.ClientConfig{
		User:            "user1-vm",
		Auth:            []ssh.AuthMethod{ssh.Password("secret")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}); err == nil {
		t.Fatal("expected password auth to be rejected for require_pubkey rule")
	}

	clientSigner := mustNewSigner(t)
	client := dialSSHClient(t, proxyAddr, "user1-vm", ssh.PublicKeys(clientSigner))
	defer client.Close()

	channel, incomingRequests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session channel: %v", err)
	}
	defer channel.Close()
	go ssh.DiscardRequests(incomingRequests)

	payload := []byte("publickey-path")
	if _, err := channel.Write(payload); err != nil {
		t.Fatalf("write session payload: %v", err)
	}
	if err := channel.CloseWrite(); err != nil {
		t.Fatalf("close session writer: %v", err)
	}

	echoed, err := io.ReadAll(channel)
	if err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("unexpected echoed payload: got %q want %q", string(echoed), string(payload))
	}
}

func TestProxyDirectTCPIPForwarding(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoServer(t)
	defer stopEcho()

	backend := startBackendSSHServer(t, backendServerOptions{
		expectedUser:     "alice",
		expectedPassword: "secret",
	})
	defer backend.stop()

	configureKnownHostsHome(t, backend.addr, backend.hostSigner.PublicKey())

	_, proxyHostKeyPath := generateSignerAndWritePrivateKeyFile(t, t.TempDir(), "proxy_host")
	cfg := newTestConfig(t, proxyHostKeyPath, "", backend.addr, "", "nas", []config.RuleConfig{
		{
			Name:            "nas-wildcard",
			Match:           "^(.*)-nas$",
			Backend:         "nas",
			BackendUsername: "$1",
		},
	})

	proxyAddr, stopProxy := startProxyServer(t, cfg)
	defer stopProxy()

	client := dialSSHClient(t, proxyAddr, "alice-nas", ssh.Password("secret"))
	defer client.Close()

	forwardConn, err := client.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("open direct-tcpip channel: %v", err)
	}
	defer forwardConn.Close()

	payload := []byte("forwarded\n")
	if _, err := forwardConn.Write(payload); err != nil {
		t.Fatalf("write forwarded payload: %v", err)
	}

	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(forwardConn, reply); err != nil {
		t.Fatalf("read forwarded payload: %v", err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatalf("unexpected forwarded payload: got %q want %q", string(reply), string(payload))
	}
}

func TestProxyNegotiatesConfiguredChannelSizing(t *testing.T) {
	backendSizingCh := make(chan channelSizingSnapshot, 1)
	backend := startBackendSSHServer(t, backendServerOptions{
		expectedUser:     "alice",
		expectedPassword: "secret",
		observeNewChannel: func(newChannel ssh.NewChannel) {
			if newChannel.ChannelType() == "session" {
				backendSizingCh <- snapshotChannelSizing(t, newChannel)
			}
		},
	})
	defer backend.stop()

	configureKnownHostsHome(t, backend.addr, backend.hostSigner.PublicKey())

	_, proxyHostKeyPath := generateSignerAndWritePrivateKeyFile(t, t.TempDir(), "proxy_host")
	cfg := newTestConfig(t, proxyHostKeyPath, "", backend.addr, "", "nas", []config.RuleConfig{
		{
			Name:            "nas-wildcard",
			Match:           "^(.*)-nas$",
			Backend:         "nas",
			BackendUsername: "$1",
		},
	})

	proxyAddr, stopProxy := startProxyServer(t, cfg)
	defer stopProxy()

	client := dialSSHClient(t, proxyAddr, "alice-nas", ssh.Password("secret"))
	defer client.Close()

	channel, incomingRequests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session channel: %v", err)
	}
	defer channel.Close()
	go ssh.DiscardRequests(incomingRequests)

	clientSizing := snapshotChannelSizing(t, channel)
	if clientSizing.MaxRemotePayload != uint32(proxysftp.ChannelMaxPacketSize) {
		t.Fatalf("unexpected client remote max payload: got %d want %d", clientSizing.MaxRemotePayload, proxysftp.ChannelMaxPacketSize)
	}
	if clientSizing.RemoteWindow != uint32(proxysftp.ChannelWindowSize) {
		t.Fatalf("unexpected client remote window: got %d want %d", clientSizing.RemoteWindow, proxysftp.ChannelWindowSize)
	}

	backendSizing := <-backendSizingCh
	if backendSizing.MaxRemotePayload != uint32(proxysftp.ChannelMaxPacketSize) {
		t.Fatalf("unexpected backend remote max payload: got %d want %d", backendSizing.MaxRemotePayload, proxysftp.ChannelMaxPacketSize)
	}
	if backendSizing.RemoteWindow != uint32(proxysftp.ChannelWindowSize) {
		t.Fatalf("unexpected backend remote window: got %d want %d", backendSizing.RemoteWindow, proxysftp.ChannelWindowSize)
	}

	largePayload := bytes.Repeat([]byte("a"), proxysftp.ChannelMaxPacketSize+8192)
	if _, err := channel.Write(largePayload); err != nil {
		t.Fatalf("write large payload: %v", err)
	}
	if err := channel.CloseWrite(); err != nil {
		t.Fatalf("close session writer: %v", err)
	}

	echoed, err := io.ReadAll(channel)
	if err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if !bytes.Equal(echoed, largePayload) {
		t.Fatalf("unexpected echoed payload length: got %d want %d", len(echoed), len(largePayload))
	}
}

type backendServerOptions struct {
	expectedUser      string
	expectedPassword  string
	expectedPublicKey ssh.PublicKey
	observeNewChannel func(ssh.NewChannel)
}

type backendServer struct {
	addr       string
	hostSigner ssh.Signer
	stop       func()
}

type directTCPIPPayload struct {
	Raddr string
	Rport uint32
	Laddr string
	Lport uint32
}

type channelSizingSnapshot struct {
	MyWindow           uint32
	RemoteWindow       uint32
	MaxIncomingPayload uint32
	MaxRemotePayload   uint32
}

func startBackendSSHServer(t *testing.T, opts backendServerOptions) *backendServer {
	t.Helper()

	hostSigner := mustNewSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for backend server: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			ChannelWindowSize:    uint32(proxysftp.ChannelWindowSize),
			ChannelMaxPacketSize: uint32(proxysftp.ChannelMaxPacketSize),
		},
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if opts.expectedPassword == "" {
				return nil, fmt.Errorf("password auth is disabled")
			}
			if conn.User() != opts.expectedUser {
				return nil, fmt.Errorf("unexpected username %q", conn.User())
			}
			if string(password) != opts.expectedPassword {
				return nil, fmt.Errorf("unexpected password")
			}
			return nil, nil
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if opts.expectedPublicKey == nil {
				return nil, fmt.Errorf("public key auth is disabled")
			}
			if conn.User() != opts.expectedUser {
				return nil, fmt.Errorf("unexpected username %q", conn.User())
			}
			if !bytes.Equal(key.Marshal(), opts.expectedPublicKey.Marshal()) {
				return nil, fmt.Errorf("unexpected public key")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					errCh <- nil
					return
				}
				errCh <- err
				return
			}

			go serveBackendSSHConn(conn, serverConfig, opts.observeNewChannel)
		}
	}()

	return &backendServer{
		addr:       listener.Addr().String(),
		hostSigner: hostSigner,
		stop: func() {
			cancel()
			_ = listener.Close()
			if err := <-errCh; err != nil {
				t.Errorf("backend server stopped with error: %v", err)
			}
		},
	}
}

func serveBackendSSHConn(rawConn net.Conn, serverConfig *ssh.ServerConfig, observeNewChannel func(ssh.NewChannel)) {
	serverConn, incomingChannels, incomingRequests, err := ssh.NewServerConn(rawConn, serverConfig)
	if err != nil {
		return
	}
	defer serverConn.Close()

	go func() {
		for req := range incomingRequests {
			switch req.Type {
			case "unit-test-global":
				_ = req.Reply(true, []byte("global-ok"))
			default:
				_ = req.Reply(false, nil)
			}
		}
	}()

	for newChannel := range incomingChannels {
		if observeNewChannel != nil {
			observeNewChannel(newChannel)
		}
		switch newChannel.ChannelType() {
		case "session":
			go serveSessionChannel(newChannel)
		case "direct-tcpip":
			go serveDirectTCPIPChannel(newChannel)
		default:
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported test channel")
		}
	}
}

func serveSessionChannel(newChannel ssh.NewChannel) {
	channel, incomingRequests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	go func() {
		for req := range incomingRequests {
			switch req.Type {
			case "unit-test-request":
				_ = req.Reply(true, nil)
			default:
				_ = req.Reply(false, nil)
			}
		}
	}()

	payload, err := io.ReadAll(channel)
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	if len(payload) > 0 {
		_, _ = channel.Write(payload)
	}
}

func serveDirectTCPIPChannel(newChannel ssh.NewChannel) {
	var payload directTCPIPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	targetConn, err := net.Dial("tcp", net.JoinHostPort(payload.Raddr, strconv.Itoa(int(payload.Rport))))
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	channel, incomingRequests, err := newChannel.Accept()
	if err != nil {
		_ = targetConn.Close()
		return
	}
	go ssh.DiscardRequests(incomingRequests)

	bridgeReadWriteClosers(channel, targetConn)
}

func bridgeReadWriteClosers(left io.ReadWriteCloser, right io.ReadWriteCloser) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}

	go func() {
		_, _ = io.Copy(left, right)
		closeBoth()
	}()
	go func() {
		_, _ = io.Copy(right, left)
		closeBoth()
	}()
}

func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for echo server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					errCh <- nil
					return
				}
				errCh <- err
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				message, err := bufio.NewReader(conn).ReadBytes('\n')
				if err != nil {
					return
				}
				_, _ = conn.Write(message)
			}(conn)
		}
	}()

	stop := func() {
		cancel()
		_ = listener.Close()
		if err := <-errCh; err != nil {
			t.Errorf("echo server stopped with error: %v", err)
		}
	}

	return listener.Addr().String(), stop
}

func startProxyServer(t *testing.T, cfg *config.Config) (string, func()) {
	t.Helper()

	server, err := proxy.NewServer(cfg, zap.NewNop(), metrics.New())
	if err != nil {
		t.Fatalf("create proxy server: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for proxy server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx, listener)
	}()

	stop := func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("proxy server stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("timed out waiting for proxy server shutdown")
		}
	}

	return listener.Addr().String(), stop
}

func dialSSHClient(t *testing.T, addr, username string, authMethod ssh.AuthMethod) *ssh.Client {
	t.Helper()

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		Config: ssh.Config{
			ChannelWindowSize:    uint32(proxysftp.ChannelWindowSize),
			ChannelMaxPacketSize: uint32(proxysftp.ChannelMaxPacketSize),
		},
		User:            username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial SSH client: %v", err)
	}

	return client
}

func configureKnownHostsHome(t *testing.T, backendAddr string, key ssh.PublicKey) {
	t.Helper()

	homeDir := t.TempDir()
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o755); err != nil {
		t.Fatalf("create temp ssh dir: %v", err)
	}

	knownHostsPath := filepath.Join(sshDir, "known_hosts")
	line := knownhosts.Line([]string{backendAddr}, key) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
}

func newTestConfig(t *testing.T, proxyHostKeyPath, proxyCredentialsKeyPath, backendAddr, backendKeyPath, backendName string, rules []config.RuleConfig) *config.Config {
	t.Helper()

	host, portText, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("split backend address: %v", err)
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}

	backendConfig := config.BackendConfig{
		Name:               backendName,
		Host:               host,
		Port:               port,
		PrivateKey:         backendKeyPath,
		FallbackToPassword: true,
	}
	if backendKeyPath != "" {
		backendConfig.FallbackToPassword = false
	}

	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			Listen:     "127.0.0.1:0",
			HostKeys:   []string{proxyHostKeyPath},
			Algorithms: testAlgorithmsConfig(),
		},
		ProxyCredentials: config.ProxyCredentialsConfig{
			PrivateKey: proxyCredentialsKeyPath,
		},
		SFTP: config.SFTPConfig{
			WindowSize:            proxysftp.ChannelWindowSize,
			MaxPacketSize:         proxysftp.ChannelMaxPacketSize,
			MaxConcurrentRequests: proxysftp.SFTPMaxConcurrentRequests,
		},
		Timeouts: config.TimeoutsConfig{
			BackendConnect:    config.Duration{Duration: 5 * time.Second},
			BackendHandshake:  config.Duration{Duration: 5 * time.Second},
			KeepaliveInterval: config.Duration{Duration: 30 * time.Second},
			KeepaliveCountMax: 3,
		},
		Backends: map[string]config.BackendConfig{
			backendName: backendConfig,
		},
		Rules: rules,
		Metrics: config.MetricsConfig{
			Enabled: false,
			Path:    "/metrics",
		},
		Logging: config.LoggingConfig{
			Level:  "error",
			Format: "json",
			Output: "stdout",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate test config: %v", err)
	}

	return cfg
}

func testAlgorithmsConfig() config.AlgorithmsConfig {
	return config.AlgorithmsConfig{
		KEX: []string{
			"curve25519-sha256",
			"ecdh-sha2-nistp521",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp256",
			"diffie-hellman-group14-sha256",
			"diffie-hellman-group14-sha1",
		},
		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-ctr",
			"aes192-ctr",
			"aes128-ctr",
		},
		MACs: []string{
			"hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512",
			"hmac-sha2-256",
			"hmac-sha1",
		},
		HostKeyAlgos: []string{
			"ssh-ed25519",
			"ecdsa-sha2-nistp521",
			"ecdsa-sha2-nistp384",
			"ecdsa-sha2-nistp256",
			"rsa-sha2-512",
			"rsa-sha2-256",
			"ssh-rsa",
		},
	}
}

func mustNewSigner(t *testing.T) ssh.Signer {
	t.Helper()

	privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	return mustNewSignerFromPrivateKey(t, privateKey)
}

func mustNewSignerFromPrivateKey(t *testing.T, privateKey *rsa.PrivateKey) ssh.Signer {
	t.Helper()

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create SSH signer: %v", err)
	}

	return signer
}

func generateSignerAndWritePrivateKeyFile(t *testing.T, dir, baseName string) (ssh.Signer, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA file key: %v", err)
	}

	signer := mustNewSignerFromPrivateKey(t, privateKey)
	path := filepath.Join(dir, baseName+".pem")

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}

	return signer, path
}

func snapshotChannelSizing(t *testing.T, channel any) channelSizingSnapshot {
	t.Helper()

	value := reflect.ValueOf(channel)
	if value.Kind() != reflect.Ptr || value.IsNil() {
		t.Fatalf("expected non-nil pointer channel, got %T", channel)
	}

	elem := value.Elem()
	return channelSizingSnapshot{
		MyWindow:           uint32(elem.FieldByName("myWindow").Uint()),
		RemoteWindow:       uint32(elem.FieldByName("remoteWin").FieldByName("win").Uint()),
		MaxIncomingPayload: uint32(elem.FieldByName("maxIncomingPayload").Uint()),
		MaxRemotePayload:   uint32(elem.FieldByName("maxRemotePayload").Uint()),
	}
}
