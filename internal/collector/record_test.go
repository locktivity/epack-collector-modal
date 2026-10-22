//go:build record

package collector

import (
	"os"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// TestRecord records a sandbox, a Modal workspace kept with known settings,
// to testdata/recordings/modal.json for the collectortest suite. It reads
// the workspace's name and its members' email addresses from
// SANDBOX_MODAL_WORKSPACE, SANDBOX_MODAL_OWNER_EMAIL,
// SANDBOX_MODAL_MANAGER_EMAIL, and SANDBOX_MODAL_MEMBER_EMAIL, and the token
// from MODAL_TOKEN_ID and MODAL_TOKEN_SECRET, and skips when any is not set.
// The recording names the workspace and the members by the kit's fakes, and
// recordCodec replaces Modal's object IDs and people's names. The value of
// any other SANDBOX_ variable becomes a stable fake, and Record writes
// nothing if one remains:
//
//	SANDBOX_MODAL_WORKSPACE=... SANDBOX_MODAL_OWNER_EMAIL=... SANDBOX_MODAL_MANAGER_EMAIL=... \
//	SANDBOX_MODAL_MEMBER_EMAIL=... MODAL_TOKEN_ID=... MODAL_TOKEN_SECRET=... \
//	go test -tags record -run 'TestRecord/^modal$' -count=1 ./internal/collector/
func TestRecord(t *testing.T) {
	t.Run("modal", func(t *testing.T) {
		fakes := map[string]string{
			"SANDBOX_MODAL_WORKSPACE":     kitWorkspaceName,
			"SANDBOX_MODAL_OWNER_EMAIL":   "owner@example.com",
			"SANDBOX_MODAL_MANAGER_EMAIL": "manager@example.com",
			"SANDBOX_MODAL_MEMBER_EMAIL":  "member@example.com",
		}
		secrets := map[string]string{tokenIDEnv: os.Getenv(tokenIDEnv), tokenSecretEnv: os.Getenv(tokenSecretEnv)}
		missing := secrets[tokenIDEnv] == "" || secrets[tokenSecretEnv] == ""
		for name := range fakes {
			missing = missing || os.Getenv(name) == ""
		}
		if missing {
			t.Skip("set SANDBOX_MODAL_WORKSPACE, SANDBOX_MODAL_OWNER_EMAIL, SANDBOX_MODAL_MANAGER_EMAIL, SANDBOX_MODAL_MEMBER_EMAIL, " +
				tokenIDEnv + ", and " + tokenSecretEnv + " to record")
		}
		identifiers := collectortest.EnvIdentifiers("SANDBOX_", fakes)
		// A member's display name and username are often their address's
		// local part, so the local parts are scrubbed wherever they appear.
		for name, fake := range fakes {
			local, _, ok := strings.Cut(os.Getenv(name), "@")
			if !ok {
				continue
			}
			if len(local) < 4 {
				t.Fatalf("the local part of %s is shorter than four characters, too short to scrub safely", name)
			}
			identifiers[local] = "kit-" + strings.Split(fake, "@")[0]
		}

		report, err := collectortest.Record(collectortest.RecordOptions{
			Spec:    Spec("record", "collectortest"),
			Run:     Run,
			Config:  map[string]any{"level": "audit"},
			Secrets: secrets,
			Out:     "testdata/recordings/modal.json",
			Scrub:   collectortest.ScrubRules{Identifiers: identifiers},
			Codec:   newRecordCodec(),
			// A call Modal refuses carries its status in these headers.
			Headers: []string{"Grpc-Status", "Grpc-Message"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.ExitCode != 0 {
			t.Errorf("the recorded run exited %d: %+v", report.ExitCode, report.Failure)
		}
		t.Logf("recorded %d responses", report.Responses)
	})
}
