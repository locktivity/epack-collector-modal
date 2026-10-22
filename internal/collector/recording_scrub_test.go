package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"testing"
)

var (
	// modalID matches a Modal object ID, such as a workspace's ac-... or a
	// user's us-...: two letters, a dash, and at least 16 letters and digits.
	modalID     = regexp.MustCompile(`\b[a-z]{2}-[A-Za-z0-9]{16,}\b`)
	fakeModalID = regexp.MustCompile(`^[a-z]{2}-kit[0-9]+$`)

	recordedEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	fakeEmail     = regexp.MustCompile(`@example\.com$`)
)

// personKeys name the JSON members, in protojson's names, that hold a
// person's display name or username.
var personKeys = []string{"memberDisplayname", "username", "userName", "createdBy", "deployedBy", "stoppedBy"}

// droppedKeys name the JSON members the collector never reads that hold a
// person's picture or their identity provider's ID for them.
var droppedKeys = []string{"avatarUrl", "createdByAvatarUrl", "idpExternalId"}

// recordCodec is grpcCodec for recording a sandbox. Before Record scrubs a
// body, it drops droppedKeys, and gives each Modal object ID, in a value or
// an object key, and each name in personKeys a stable fake, the same one
// wherever the value appears. Record's own rules don't know these values,
// since nothing in the environment holds them.
type recordCodec struct {
	grpcCodec
	mu        sync.Mutex
	fakes     map[string]string
	idCount   int
	nameCount int
}

func newRecordCodec() *recordCodec {
	return &recordCodec{fakes: map[string]string{}}
}

func (c *recordCodec) DecodeRequest(op string, header http.Header, body []byte) ([]byte, error) {
	return c.rewrite(c.grpcCodec.DecodeRequest(op, header, body))
}

func (c *recordCodec) DecodeResponse(op string, header http.Header, body []byte) ([]byte, error) {
	return c.rewrite(c.grpcCodec.DecodeResponse(op, header, body))
}

func (c *recordCodec) rewrite(raw []byte, err error) ([]byte, error) {
	if err != nil || raw == nil {
		return raw, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return json.Marshal(c.walk(doc))
}

// walk visits object members in sorted order, so a recording numbers its
// fakes the same way each time.
func (c *recordCodec) walk(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for _, key := range slices.Sorted(maps.Keys(v)) {
			name, isString := v[key].(string)
			switch {
			case slices.Contains(droppedKeys, key):
			case slices.Contains(personKeys, key) && isString && name != "":
				out[key] = c.fake(name, func() string {
					c.nameCount++
					return fmt.Sprintf("kit-person-%d", c.nameCount)
				})
			default:
				out[c.replaceIDs(key)] = c.walk(v[key])
			}
		}
		return out
	case []any:
		for i := range v {
			v[i] = c.walk(v[i])
		}
		return v
	case string:
		return c.replaceIDs(v)
	}
	return v
}

// replaceIDs gives each Modal object ID in s its fake, and leaves a fake
// as it is.
func (c *recordCodec) replaceIDs(s string) string {
	return modalID.ReplaceAllStringFunc(s, func(id string) string {
		if fakeModalID.MatchString(id) {
			return id
		}
		return c.fake(id, func() string {
			c.idCount++
			return fmt.Sprintf("%s-kit%0*d", id[:2], len(id)-6, c.idCount)
		})
	})
}

func (c *recordCodec) fake(value string, next func() string) string {
	if fake, ok := c.fakes[value]; ok {
		return fake
	}
	fake := next()
	c.fakes[value] = fake
	return fake
}

func TestRecordCodecReplacesIDsAndNames(t *testing.T) {
	c := newRecordCodec()
	got, err := c.rewrite([]byte(`{
		"members": [{"memberDisplayname": "jo", "userId": "us-AbCdEfGhIjKlMnOpQrStUv", "avatarUrl": "https://avatars.example/u/1", "idpExternalId": "123", "joinedAt": 1761200000.5}],
		"createdBy": {"userId": "us-AbCdEfGhIjKlMnOpQrStUv", "username": "jo"},
		"functions": {"web": "fu-0123456789abcdefghijkl"},
		"functionInfoSummaries": {"fu-0123456789abcdefghijkl": {"webFunction": true}},
		"name": "db-credentials",
		"appId": "ap-kit0000000000000000009"
	}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"appId":"ap-kit0000000000000000009","createdBy":{"userId":"us-kit0000000000000000001","username":"kit-person-1"},"functionInfoSummaries":{"fu-kit0000000000000000002":{"webFunction":true}},"functions":{"web":"fu-kit0000000000000000002"},"members":[{"joinedAt":1761200000.5,"memberDisplayname":"kit-person-1","userId":"us-kit0000000000000000001"}],"name":"db-credentials"}`
	if string(got) != want {
		t.Errorf("rewrote to\n%s\nwant\n%s", got, want)
	}
	if again, _ := c.rewrite([]byte(`{"appId": "us-AbCdEfGhIjKlMnOpQrStUv"}`), nil); string(again) != `{"appId":"us-kit0000000000000000001"}` {
		t.Errorf("a second body gave the same ID %s", again)
	}
}

// TestRecordingsScrubbed fails while a committed recording still holds a
// Modal object ID other than recordCodec's fakes, a member that
// recordCodec drops, or an email address outside example.com.
func TestRecordingsScrubbed(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "recordings", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range modalID.FindAll(raw, -1) {
			if !fakeModalID.Match(id) {
				t.Errorf("%s: holds a Modal object ID", path)
			}
		}
		for _, key := range droppedKeys {
			if bytes.Contains(raw, []byte(`"`+key+`"`)) {
				t.Errorf("%s: holds %s", path, key)
			}
		}
		for _, email := range recordedEmail.FindAll(raw, -1) {
			if !fakeEmail.Match(email) {
				t.Errorf("%s: holds an email address outside example.com", path)
			}
		}
	}
}
