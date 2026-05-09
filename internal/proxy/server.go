package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"ssh-proxy/internal/auth"
	"ssh-proxy/internal/backend"
	"ssh-proxy/internal/config"
	"ssh-proxy/internal/metrics"
	"ssh-proxy/internal/router"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	cfg           *config.Config
	logger        *zap.Logger
	metrics       *metrics.Registry
	authenticator *auth.Authenticator
	dialer        *backend.Dialer
	serverConfig  *ssh.ServerConfig
}

func NewServer(cfg *config.Config, logger *zap.Logger, metricRegistry *metrics.Registry) (*Server, error) {
	routerInstance, err := router.New(cfg)
	if err != nil {
		return nil, err
	}

	dialer, err := backend.NewDialer(cfg, logger, metricRegistry)
	if err != nil {
		return nil, err
	}

	authenticator := auth.NewAuthenticator(routerInstance, dialer, logger, metricRegistry)
	serverConfig, err := buildServerConfig(cfg, authenticator, logger)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:           cfg,
		logger:        logger,
		metrics:       metricRegistry,
		authenticator: authenticator,
		dialer:        dialer,
		serverConfig:  serverConfig,
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.Proxy.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Proxy.Listen, err)
	}

	return s.Serve(ctx, listener)
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	defer listener.Close()

	s.logger.Info("ssh proxy listening", zap.String("listen", listener.Addr().String()))

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}

			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				s.logger.Warn("temporary accept failure", zap.Error(err))
				continue
			}

			return fmt.Errorf("accept ssh connection: %w", err)
		}

		go s.handleConn(conn)
	}
}

func buildServerConfig(cfg *config.Config, authenticator *auth.Authenticator, logger *zap.Logger) (*ssh.ServerConfig, error) {
	serverConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges:         append([]string(nil), cfg.Proxy.Algorithms.KEX...),
			Ciphers:              append([]string(nil), cfg.Proxy.Algorithms.Ciphers...),
			MACs:                 append([]string(nil), cfg.Proxy.Algorithms.MACs...),
			ChannelWindowSize:    uint32(cfg.SFTP.WindowSize),
			ChannelMaxPacketSize: uint32(cfg.SFTP.MaxPacketSize),
		},
		MaxAuthTries:      6,
		PasswordCallback:  authenticator.PasswordCallback,
		PublicKeyCallback: authenticator.PublicKeyCallback,
		ServerVersion:     "SSH-2.0-ssh-proxy",
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			fields := []zap.Field{
				zap.String("username", conn.User()),
				zap.String("method", method),
				zap.String("remote_addr", conn.RemoteAddr().String()),
			}
			if err == nil {
				logger.Info("client authentication succeeded", fields...)
				return
			}

			fields = append(fields, zap.Error(err))
			logger.Warn("client authentication failed", fields...)
		},
	}

	for _, path := range cfg.Proxy.HostKeys {
		keyData, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read host key %q: %w", path, err)
		}

		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse host key %q: %w", path, err)
		}

		serverConfig.AddHostKey(signer)
	}

	return serverConfig, nil
}
