package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"ssh-proxy/internal/metrics"
	"ssh-proxy/internal/router"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	MethodPassword  = "password"
	MethodPublicKey = "publickey"

	permissionStateID        = "state_id"
	permissionAuthMethod     = "auth_method"
	permissionBackend        = "backend"
	permissionBackendUser    = "backend_username"
	permissionRule           = "rule"
	permissionKeyFingerprint = "publickey_fingerprint"
)

type PasswordVerifier interface {
	VerifyPassword(ctx context.Context, match *router.MatchResult, password []byte) error
}

type SessionState struct {
	ID        string
	Match     *router.MatchResult
	Method    string
	Password  []byte
	PublicKey ssh.PublicKey
}

func (s *SessionState) ClearSecret() {
	zeroSecret(s.Password)
	s.Password = nil
}

type Authenticator struct {
	router   *router.Router
	verifier PasswordVerifier
	logger   *zap.Logger
	metrics  *metrics.Registry

	mu     sync.Mutex
	states map[string]*SessionState
}

func NewAuthenticator(router *router.Router, verifier PasswordVerifier, logger *zap.Logger, metrics *metrics.Registry) *Authenticator {
	return &Authenticator{
		router:   router,
		verifier: verifier,
		logger:   logger,
		metrics:  metrics,
		states:   make(map[string]*SessionState),
	}
}

func (a *Authenticator) PasswordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	startedAt := time.Now()
	secret := cloneSecret(password)
	zeroSecret(password)

	match, err := a.router.Match(conn.User())
	if err != nil {
		zeroSecret(secret)
		a.metrics.RecordAuthAttempt(MethodPassword, "rejected", "", time.Since(startedAt))
		return nil, err
	}

	if match.RequirePubkey {
		zeroSecret(secret)
		a.metrics.RecordAuthAttempt(MethodPassword, "rejected", match.BackendName, time.Since(startedAt))
		return nil, fmt.Errorf("publickey required")
	}

	if err := a.verifier.VerifyPassword(context.Background(), match, secret); err != nil {
		zeroSecret(secret)
		a.metrics.RecordAuthAttempt(MethodPassword, "rejected", match.BackendName, time.Since(startedAt))
		return nil, err
	}

	permissions, err := a.storeState(match, MethodPassword, secret, nil)
	if err != nil {
		zeroSecret(secret)
		a.metrics.RecordAuthAttempt(MethodPassword, "error", match.BackendName, time.Since(startedAt))
		return nil, err
	}

	a.metrics.RecordAuthAttempt(MethodPassword, "success", match.BackendName, time.Since(startedAt))
	return permissions, nil
}

func (a *Authenticator) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	startedAt := time.Now()

	match, err := a.router.Match(conn.User())
	if err != nil {
		a.metrics.RecordAuthAttempt(MethodPublicKey, "rejected", "", time.Since(startedAt))
		return nil, err
	}

	permissions, err := a.storeState(match, MethodPublicKey, nil, key)
	if err != nil {
		a.metrics.RecordAuthAttempt(MethodPublicKey, "error", match.BackendName, time.Since(startedAt))
		return nil, err
	}

	a.metrics.RecordAuthAttempt(MethodPublicKey, "success", match.BackendName, time.Since(startedAt))
	return permissions, nil
}

func (a *Authenticator) ConsumeState(perms *ssh.Permissions) (*SessionState, error) {
	if perms == nil || perms.Extensions == nil {
		return nil, fmt.Errorf("missing auth permissions")
	}

	stateID := perms.Extensions[permissionStateID]
	if stateID == "" {
		return nil, fmt.Errorf("missing auth state id")
	}

	a.mu.Lock()
	state, ok := a.states[stateID]
	if ok {
		delete(a.states, stateID)
	}
	a.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("auth state %q not found", stateID)
	}

	return state, nil
}

func (a *Authenticator) storeState(match *router.MatchResult, method string, password []byte, key ssh.PublicKey) (*ssh.Permissions, error) {
	stateID, err := newStateID()
	if err != nil {
		return nil, fmt.Errorf("generate auth state id: %w", err)
	}

	state := &SessionState{
		ID:        stateID,
		Match:     match,
		Method:    method,
		Password:  password,
		PublicKey: key,
	}

	a.mu.Lock()
	a.states[stateID] = state
	a.mu.Unlock()

	permissions := &ssh.Permissions{
		Extensions: map[string]string{
			permissionStateID:     stateID,
			permissionAuthMethod:  method,
			permissionBackend:     match.BackendName,
			permissionBackendUser: match.BackendUsername,
			permissionRule:        match.RuleName,
		},
	}

	if key != nil {
		permissions.Extensions[permissionKeyFingerprint] = fingerprintPublicKey(key)
	}

	return permissions, nil
}

func newStateID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
