package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"ssh-proxy/internal/auth"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func (s *Server) handleConn(rawConn net.Conn) {
	serverConn, incomingChannels, incomingRequests, err := ssh.NewServerConn(rawConn, s.serverConfig)
	if err != nil {
		s.logger.Warn("ssh handshake failed", zap.String("remote_addr", rawConn.RemoteAddr().String()), zap.Error(err))
		return
	}
	defer serverConn.Close()

	state, err := s.authenticator.ConsumeState(serverConn.Permissions)
	if err != nil {
		s.logger.Error("resolve auth state failed", zap.String("remote_addr", serverConn.RemoteAddr().String()), zap.Error(err))
		return
	}

	sessionLogger := s.sessionLogger(serverConn, state)
	backendSession, err := s.dialer.Dial(context.Background(), state.Match, state.Method, state.Password)
	state.ClearSecret()
	if err != nil {
		s.metrics.RecordConnectionResult(state.Match.BackendName, state.Method, "backend_dial_error")
		sessionLogger.Warn("backend dial failed", zap.Error(err))
		return
	}
	defer backendSession.Close()

	s.metrics.RecordConnectionResult(state.Match.BackendName, state.Method, "success")
	sessionLogger.Info("session started")
	defer sessionLogger.Info("session stopped")

	closeSession := func() {
		_ = serverConn.Close()
		_ = backendSession.Close()
	}

	go s.forwardGlobalRequests(backendSession.Conn, incomingRequests, closeSession, sessionLogger)
	go s.forwardGlobalRequests(serverConn, backendSession.IncomingRequests, closeSession, sessionLogger)
	go s.forwardClientChannels(incomingChannels, backendSession, sessionLogger)
	go s.forwardBackendChannels(serverConn, backendSession, sessionLogger)

	errCh := make(chan error, 2)
	go func() {
		errCh <- serverConn.Wait()
	}()
	go func() {
		errCh <- backendSession.Wait()
	}()

	waitErr := <-errCh
	if waitErr != nil && !errors.Is(waitErr, net.ErrClosed) && !errors.Is(waitErr, io.EOF) && !strings.Contains(waitErr.Error(), "EOF") {
		sessionLogger.Debug("session ended with error", zap.Error(waitErr))
	}
}

func (s *Server) sessionLogger(conn *ssh.ServerConn, state *auth.SessionState) *zap.Logger {
	clientIP, clientPort := splitAddr(conn.RemoteAddr())

	return s.logger.With(
		zap.String("session_id", shortSessionID(conn.SessionID())),
		zap.String("client_ip", clientIP),
		zap.Int("client_port", clientPort),
		zap.String("username", conn.User()),
		zap.String("backend_username", state.Match.BackendUsername),
		zap.String("backend", state.Match.BackendName),
		zap.String("backend_addr", state.Match.Backend.Address()),
		zap.String("auth_method", state.Method),
		zap.String("rule", state.Match.RuleName),
	)
}

func shortSessionID(sessionID []byte) string {
	encoded := hex.EncodeToString(sessionID)
	if len(encoded) > 12 {
		return encoded[:12]
	}
	return encoded
}

func splitAddr(addr net.Addr) (string, int) {
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return host, 0
	}

	return host, port
}
