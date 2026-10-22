package collector

import (
	"fmt"
	"slices"
)

// Config is the collector's configuration from epack.yaml. The collector
// reads the workspace the token belongs to, so it has no settings of its
// own. The SDK reads the level key itself, through
// componentsdk.CollectorContext.Level.
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
		if key != "level" {
			return Config{}, fmt.Errorf("the collector has no setting named %s. It reads the workspace the token belongs to, and level is its only setting", key)
		}
	}
	return Config{}, nil
}
