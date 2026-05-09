package proxy

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"ssh-proxy/internal/backend"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func (s *Server) forwardClientChannels(incoming <-chan ssh.NewChannel, backendSession *backend.Session, logger *zap.Logger) {
	for newChannel := range incoming {
		go func(newChannel ssh.NewChannel) {
			backendChannel, backendRequests, err := backendSession.Conn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
			if err != nil {
				reason, message := channelRejection(err)
				_ = newChannel.Reject(reason, message)
				logger.Warn("open backend channel failed", zap.String("channel_type", newChannel.ChannelType()), zap.Error(err))
				return
			}

			clientChannel, clientRequests, err := newChannel.Accept()
			if err != nil {
				_ = backendChannel.Close()
				logger.Warn("accept client channel failed", zap.String("channel_type", newChannel.ChannelType()), zap.Error(err))
				return
			}

			s.bridgeChannel(clientChannel, backendChannel, clientRequests, backendRequests, backendSession.Match.BackendName, logger)
		}(newChannel)
	}
}

func (s *Server) forwardBackendChannels(clientConn *ssh.ServerConn, backendSession *backend.Session, logger *zap.Logger) {
	for newChannel := range backendSession.IncomingChannels {
		go func(newChannel ssh.NewChannel) {
			clientChannel, clientRequests, err := clientConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
			if err != nil {
				_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
				logger.Warn("open client channel failed", zap.String("channel_type", newChannel.ChannelType()), zap.Error(err))
				return
			}

			backendChannel, backendRequests, err := newChannel.Accept()
			if err != nil {
				_ = clientChannel.Close()
				logger.Warn("accept backend channel failed", zap.String("channel_type", newChannel.ChannelType()), zap.Error(err))
				return
			}

			s.bridgeChannel(clientChannel, backendChannel, clientRequests, backendRequests, backendSession.Match.BackendName, logger)
		}(newChannel)
	}
}

func (s *Server) bridgeChannel(clientChannel ssh.Channel, backendChannel ssh.Channel, clientRequests <-chan *ssh.Request, backendRequests <-chan *ssh.Request, backendName string, logger *zap.Logger) {
	var (
		closeOnce sync.Once
		copyGroup sync.WaitGroup
	)

	closeChannels := func() {
		closeOnce.Do(func() {
			_ = clientChannel.Close()
			_ = backendChannel.Close()
		})
	}

	go s.forwardChannelRequests(backendChannel, clientRequests, closeChannels, logger)
	go s.forwardChannelRequests(clientChannel, backendRequests, closeChannels, logger)

	copyGroup.Add(3)
	go s.copyStream(backendChannel, clientChannel, backendName, "up", true, &copyGroup, logger)
	go s.copyStream(clientChannel, backendChannel, backendName, "down", true, &copyGroup, logger)
	go s.copyExtendedStream(clientChannel.Stderr(), backendChannel.Stderr(), backendName, "down", &copyGroup, logger)

	go func() {
		copyGroup.Wait()
		closeChannels()
	}()
}

func (s *Server) forwardGlobalRequests(dst ssh.Conn, incoming <-chan *ssh.Request, closeSession func(), logger *zap.Logger) {
	for req := range incoming {
		ok, payload, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(err == nil && ok, payload)
		}
		if err != nil {
			logger.Warn("forward global request failed", zap.String("request_type", req.Type), zap.Error(err))
			closeSession()
			return
		}
	}
}

func (s *Server) forwardChannelRequests(dst ssh.Channel, incoming <-chan *ssh.Request, closeChannels func(), logger *zap.Logger) {
	for req := range incoming {
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			_ = req.Reply(err == nil && ok, nil)
		}
		if err != nil {
			logger.Warn("forward channel request failed", zap.String("request_type", req.Type), zap.Error(err))
			closeChannels()
			return
		}
	}
}

func (s *Server) copyStream(dst ssh.Channel, src ssh.Channel, backendName, direction string, closeWrite bool, copyGroup *sync.WaitGroup, logger *zap.Logger) {
	defer copyGroup.Done()

	count, err := io.Copy(dst, src)
	s.metrics.AddBytes(backendName, direction, count)
	if closeWrite {
		_ = dst.CloseWrite()
	}
	if err != nil && !errors.Is(err, io.EOF) {
		logger.Debug("channel stream copy failed", zap.String("direction", direction), zap.Error(err))
	}
}

func (s *Server) copyExtendedStream(dst io.Writer, src io.Reader, backendName, direction string, copyGroup *sync.WaitGroup, logger *zap.Logger) {
	defer copyGroup.Done()

	count, err := io.Copy(dst, src)
	s.metrics.AddBytes(backendName, direction, count)
	if err != nil && !errors.Is(err, io.EOF) {
		logger.Debug("channel stderr copy failed", zap.String("direction", direction), zap.Error(err))
	}
}

func channelRejection(err error) (ssh.RejectionReason, string) {
	var openErr *ssh.OpenChannelError
	if errors.As(err, &openErr) {
		return openErr.Reason, openErr.Message
	}
	return ssh.ConnectionFailed, fmt.Sprintf("open channel failed: %v", err)
}
