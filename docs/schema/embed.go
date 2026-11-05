// Package schema embeds the JSON Schema of the collector's detailed
// artifact, which the collector checks its output against when it emits,
// the methods of its access-posture artifact, and its trace map, which the
// SDK writes into the build file of every pack.
package schema

import (
	_ "embed"
	"encoding/json"
)

// Artifact is the schema in v1.0.0.json.
//
//go:embed v1.0.0.json
var Artifact []byte

// methods is methods.json. For the access-posture artifact, it holds one
// plain sentence on how each value is measured.
//
//go:embed methods.json
var methods []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Methods returns the sentences in methods.json for
// componentsdk.CollectorSpec.Methods. The SDK writes each one as the
// x-epack-method of its field in the SDK's schema for the type.
func Methods() map[string]map[string]string {
	var bySchema map[string]map[string]string
	if err := json.Unmarshal(methods, &bySchema); err != nil {
		panic("docs/schema/methods.json: " + err.Error())
	}
	return bySchema
}
