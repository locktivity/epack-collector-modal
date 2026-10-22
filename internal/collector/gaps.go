package collector

import (
	"github.com/locktivity/epack/componentsdk"
)

// gapLog records each value the collector leaves out of its artifact in the
// run's recorder. The SDK writes the gaps into the collector result, with
// the code componentsdk.Classify gives each error and the call it came from.
// Its methods mark themselves with Recorder.Helper, so each gap's source
// names the line that called them.
type gapLog struct {
	rec *componentsdk.Recorder
}

// notCollected records the value at pointer as left out because of err.
// opts add details, such as the role a permission_denied gap lacks.
func (l gapLog) notCollected(err error, pointer string, opts ...componentsdk.GapOption) {
	l.rec.Helper()
	l.rec.NotCollected(location(pointer), err, opts...)
}

func location(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: artifactPath, Pointer: pointer}
}
