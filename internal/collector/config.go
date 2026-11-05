package collector

import (
	"fmt"
	"slices"
)

// Config is the collector's configuration from epack.yaml. The collector
// reads the workspace the token belongs to, so it has no settings of its
// own. The SDK reads the level and collect keys itself, through
// componentsdk.CollectorContext.Level and componentsdk.Selected.
type Config struct{}

// ParseConfig checks the collector's config. A key the collector does not
// know is an error, which Run reports as a config error (exit 2).
func ParseConfig(raw map[string]any) (Config, error) {
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if key != "level" && key != "collect" {
			return Config{}, fmt.Errorf("the collector has no setting named %s. It reads the workspace the token belongs to, and its only settings are level and collect", key)
		}
	}
	return Config{}, nil
}
