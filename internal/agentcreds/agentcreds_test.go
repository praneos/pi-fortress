package agentcreds

import (
	"slices"
	"testing"

	"pi-fortress/internal/secrets"
)

// The file holds the two placeholders of the slot and nothing live. A
// caller that edits the scopes does not change the next file.
func TestDocHoldsPlaceholdersOnly(t *testing.T) {
	const slot = "a1b2c3d4e5f67890"
	oauth := Doc(slot)["claudeAiOauth"].(map[string]any)
	if got, want := oauth["accessToken"], secrets.Placeholder(slot, "CLAUDE_OAT"); got != want {
		t.Errorf("accessToken = %v, want %v", got, want)
	}
	if got, want := oauth["refreshToken"], secrets.Placeholder(slot, "CLAUDE_ORT"); got != want {
		t.Errorf("refreshToken = %v, want %v", got, want)
	}
	if oauth["expiresAt"] != 0 {
		t.Errorf("expiresAt = %v, want 0 so that the first use refreshes", oauth["expiresAt"])
	}
	scopes := oauth["scopes"].([]string)
	want := slices.Clone(scopes)
	scopes[0] = "changed"
	if got := Doc(slot)["claudeAiOauth"].(map[string]any)["scopes"].([]string); !slices.Equal(got, want) {
		t.Errorf("scopes = %v, want %v", got, want)
	}
}
