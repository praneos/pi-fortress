package admin

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"pi-fortress/internal/fetch"
)

func (c *Config) sourcesPath() string { return filepath.Join(c.PolicyDir, "sources.json") }

func (c *Config) Feeds() (*fetch.Spec, error) {
	raw, err := os.ReadFile(c.sourcesPath())
	if err != nil {
		return nil, err
	}
	var spec fetch.Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// SetFeedEnabled writes sources.json again with the enabled flag of the
// feed. Only the fields that fetch.Spec knows stay after the round trip.
func (c *Config) SetFeedEnabled(id string, on bool) error {
	return c.withEditLock(func() error { return c.setFeedEnabled(id, on) })
}

func (c *Config) setFeedEnabled(id string, on bool) error {
	spec, err := c.Feeds()
	if err != nil {
		return err
	}
	found := false
	for i := range spec.Feeds {
		if spec.Feeds[i].ID != id {
			continue
		}
		found = true
		if on {
			spec.Feeds[i].Enabled = nil
		} else {
			spec.Feeds[i].Enabled = &on
		}
	}
	if !found {
		return errors.New("unknown feed " + id)
	}
	raw, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(c.sourcesPath(), append(raw, '\n'), 0644)
}
