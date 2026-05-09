package router

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ssh-proxy/internal/config"
)

var ErrNoMatchingRule = fmt.Errorf("no matching routing rule")

type Router struct {
	rules    []compiledRule
	backends map[string]config.BackendConfig
}

type compiledRule struct {
	name            string
	regex           *regexp.Regexp
	backend         string
	backendUsername string
	requirePubkey   bool
}

func New(cfg *config.Config) (*Router, error) {
	rules := make([]compiledRule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		re, err := regexp.Compile(rule.Match)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", rule.Name, err)
		}

		rules = append(rules, compiledRule{
			name:            rule.Name,
			regex:           re,
			backend:         rule.Backend,
			backendUsername: rule.BackendUsername,
			requirePubkey:   rule.RequirePubkey,
		})
	}

	return &Router{
		rules:    rules,
		backends: cfg.Backends,
	}, nil
}

func (r *Router) Match(username string) (*MatchResult, error) {
	for _, rule := range r.rules {
		groups := rule.regex.FindStringSubmatch(username)
		if groups == nil {
			continue
		}

		backend, ok := r.backends[rule.backend]
		if !ok {
			return nil, fmt.Errorf("rule %q references unknown backend %q", rule.name, rule.backend)
		}

		return &MatchResult{
			RuleName:        rule.name,
			BackendName:     rule.backend,
			Backend:         backend,
			BackendUsername: expandCaptures(rule.backendUsername, groups),
			RequirePubkey:   rule.requirePubkey,
		}, nil
	}

	return nil, ErrNoMatchingRule
}

func expandCaptures(input string, groups []string) string {
	result := input
	for idx := len(groups) - 1; idx >= 1; idx-- {
		placeholder := "$" + strconv.Itoa(idx)
		result = strings.ReplaceAll(result, placeholder, groups[idx])
	}
	return result
}
