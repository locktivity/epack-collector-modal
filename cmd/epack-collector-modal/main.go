// epack-collector-modal is an epack collector built with the Component SDK.
package main

import (
	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-modal/internal/collector"
)

// Version and Commit are set by ldflags at build time.
var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(collector.Spec(Version, Commit), collector.Run)
}
