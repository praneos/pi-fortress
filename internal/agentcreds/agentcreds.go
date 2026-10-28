// Package agentcreds makes the credentials.json that an agent gets: the
// placeholders of one slot and no live token. pf enroll and pf www both
// show it, so it has its own package, and pf www does not import pf enroll
// for it.
package agentcreds

import "pi-fortress/internal/secrets"

var claudeAIScopes = []string{
	"user:file_upload",
	"user:inference",
	"user:mcp_servers",
	"user:profile",
	"user:sessions:claude_code",
}

func Doc(slot string) map[string]any {
	return map[string]any{
		"claudeAiOauth": map[string]any{
			"accessToken":  secrets.Placeholder(slot, "CLAUDE_OAT"),
			"refreshToken": secrets.Placeholder(slot, "CLAUDE_ORT"),
			"expiresAt":    0,
			"scopes":       append([]string(nil), claudeAIScopes...),
		},
	}
}
