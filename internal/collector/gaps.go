package collector

import (
	"github.com/locktivity/epack/componentsdk"
)

// gapLog records each value the collector leaves out of its artifacts in the
// run's recorder. The SDK writes the gaps into the collector result, with
// the code componentsdk.Classify gives each error and the call it came from.
// Its methods mark themselves with Recorder.Helper, so each gap's source
// names the line that called them.
type gapLog struct {
	rec *componentsdk.Recorder
}

// notCollected records the detailed artifact's value at pointer as left out
// because of err.
// opts add details, such as the role a permission_denied gap lacks.
func (l gapLog) notCollected(err error, pointer string, opts ...componentsdk.AdviceOption) {
	l.rec.Helper()
	l.rec.NotCollected(location(pointer), err, opts...)
}

// access records the access-posture value at pointer as left out because
// of err.
func (l gapLog) access(err error, pointer string, opts ...componentsdk.AdviceOption) {
	l.rec.Helper()
	l.rec.NotCollected(accessLocation(pointer), err, opts...)
}

// partial records the access-posture value at pointer as left out because
// unmeasured of the items it counts could not be measured, with err saying
// why.
func (l gapLog) partial(pointer string, unmeasured int, err error) {
	l.rec.Helper()
	l.rec.Partial(accessLocation(pointer), unmeasured, err)
}

// unsupported records the access-posture value at pointer as one Modal does
// not report, with reason.
func (l gapLog) unsupported(pointer, reason string) {
	l.rec.Helper()
	l.rec.NotCollectedCode(accessLocation(pointer), componentsdk.CodeUnsupported, reason)
}

// notRead records the access-posture value at pointer as one Modal reports
// and the collector does not read, with a detail that names the call that
// reports it.
func (l gapLog) notRead(pointer, detail string) {
	l.rec.Helper()
	l.rec.NotCollectedCode(accessLocation(pointer), componentsdk.CodeNotRead, detail)
}

func accessLocation(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: accessPath, Pointer: pointer}
}

func location(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: artifactPath, Pointer: pointer}
}
