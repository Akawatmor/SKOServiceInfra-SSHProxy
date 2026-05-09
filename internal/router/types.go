package router

import "ssh-proxy/internal/config"

type MatchResult struct {
	RuleName        string
	BackendName     string
	Backend         config.BackendConfig
	BackendUsername string
	RequirePubkey   bool
}
