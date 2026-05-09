package backend

import (
	"context"
	"sync"
	"time"

	"ssh-proxy/internal/metrics"
	"ssh-proxy/internal/router"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type Session struct {
	Conn             ssh.Conn
	IncomingChannels <-chan ssh.NewChannel
	IncomingRequests <-chan *ssh.Request
	Match            *router.MatchResult
	AuthMethod       string

	logger    *zap.Logger
	metrics   *metrics.Registry
	startedAt time.Time
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func NewSession(conn ssh.Conn, incomingChannels <-chan ssh.NewChannel, incomingRequests <-chan *ssh.Request, match *router.MatchResult, authMethod string, keepaliveInterval time.Duration, keepaliveCountMax int, logger *zap.Logger, metricRegistry *metrics.Registry) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	session := &Session{
		Conn:             conn,
		IncomingChannels: incomingChannels,
		IncomingRequests: incomingRequests,
		Match:            match,
		AuthMethod:       authMethod,
		logger:           logger,
		metrics:          metricRegistry,
		startedAt:        time.Now(),
		cancel:           cancel,
	}

	metricRegistry.IncActive(match.BackendName)
	go session.runKeepalive(ctx, keepaliveInterval, keepaliveCountMax)

	return session
}

func (s *Session) Close() error {
	var closeErr error

	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.metrics.DecActive(s.Match.BackendName)
		s.metrics.ObserveConnectionDuration(s.Match.BackendName, time.Since(s.startedAt))
		closeErr = s.Conn.Close()
	})

	return closeErr
}

func (s *Session) Wait() error {
	return s.Conn.Wait()
}

func (s *Session) runKeepalive(ctx context.Context, interval time.Duration, maxFailures int) {
	if interval <= 0 || maxFailures <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok, _, err := s.Conn.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil || !ok {
				failures++
				if failures >= maxFailures {
					s.logger.Warn("backend keepalive failed", zap.String("backend", s.Match.BackendName), zap.Int("failures", failures), zap.Error(err))
					_ = s.Close()
					return
				}
				continue
			}

			failures = 0
		}
	}
}
