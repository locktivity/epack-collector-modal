package modal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
	"google.golang.org/protobuf/proto"
)

// TestCallsOverHTTP2 runs calls through the SDK's client against an HTTP/2
// server that answers as Modal does. The kit's replays can't cover this,
// since they send no trailers, and a status that arrives after the body
// comes in them.
func TestCallsOverHTTP2(t *testing.T) {
	t.Run("a message with its status in the trailers", func(t *testing.T) {
		var info *pb.TokenInfoGetResponse
		err := callServer(t, func(w http.ResponseWriter, r *http.Request) {
			checkRequest(t, r, "TokenInfoGet")
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
			payload, _ := proto.Marshal(pb.TokenInfoGetResponse_builder{WorkspaceId: "ac-test", WorkspaceName: "test-workspace"}.Build())
			_, _ = w.Write(frame(payload))
			w.Header().Set("Grpc-Status", "0")
		}, func(c *Client) (err error) {
			info, err = c.TokenInfo(t.Context())
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if info.GetWorkspaceId() != "ac-test" || info.GetWorkspaceName() != "test-workspace" {
			t.Errorf("workspace %q %q, want ac-test test-workspace", info.GetWorkspaceId(), info.GetWorkspaceName())
		}
	})

	t.Run("an error in the trailers", func(t *testing.T) {
		err := callServer(t, func(w http.ResponseWriter, r *http.Request) {
			checkRequest(t, r, "WorkspaceMembersList")
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Grpc-Status", "7")
			w.Header().Set("Grpc-Message", "User%20test%20does%20not%20have%20manage%20access")
		}, func(c *Client) error {
			_, err := c.ListMembers(t.Context())
			return err
		})
		if got := componentsdk.Classify(err); got != componentsdk.CodePermissionDenied {
			t.Errorf("code %s, want permission_denied: %v", got, err)
		}
		if err == nil || !strings.Contains(err.Error(), "PERMISSION_DENIED: User test does not have manage access") {
			t.Errorf("error %v does not carry the decoded status", err)
		}
	})

	t.Run("an error with no body", func(t *testing.T) {
		err := callServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "16")
			w.Header().Set("Grpc-Message", "Token not found")
		}, func(c *Client) error {
			_, err := c.TokenInfo(t.Context())
			return err
		})
		if got := componentsdk.Classify(err); got != componentsdk.CodeAuthFailed {
			t.Errorf("code %s, want auth_failed: %v", got, err)
		}
	})
}

func TestUnframe(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty":      nil,
		"compressed": {1, 0, 0, 0, 1, 8},
		"short":      {0, 0, 0, 0, 2, 8},
		"long":       {0, 0, 0, 0, 1, 8, 1},
	} {
		if _, err := unframe(body); err == nil {
			t.Errorf("%s: unframe(%v) succeeded", name, body)
		}
	}
	if got, err := unframe(frame([]byte{8, 1})); err != nil || string(got) != "\x08\x01" {
		t.Errorf("unframe(frame) = %v, %v", got, err)
	}
}

// callServer runs do with a Client whose calls go through the SDK's client
// to an HTTP/2 server that answers with handler.
func callServer(t *testing.T, handler http.HandlerFunc, do func(*Client) error) error {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	var callErr error
	componentsdk.RunInProcess(componentsdk.CollectorSpec{Name: "modal-client-test"}, func(ctx componentsdk.CollectorContext) error {
		client := NewClient(componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
			CredentialHosts:   []string{APIHost},
			CredentialHeaders: CredentialHeaders,
			ClassifyResponse:  Classify,
			ClassifySuccess:   true,
			VendorCode:        VendorCode,
		}), "ak-test", "as-test")
		callErr = do(client)
		return nil
	}, componentsdk.InProcessOptions{Transport: toServer{srv}})
	return callErr
}

// toServer sends each request to srv in place of Modal's API.
type toServer struct{ srv *httptest.Server }

func (s toServer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Host = s.srv.Listener.Addr().String()
	return s.srv.Client().Transport.RoundTrip(req)
}

// checkRequest checks that r is a gRPC call to method that carries the
// token and one empty message.
func checkRequest(t *testing.T, r *http.Request, method string) {
	t.Helper()
	if r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != "/modal.client.ModalClient/"+method {
		t.Errorf("request %s %s over %s, want POST %s over HTTP/2", r.Method, r.URL.Path, r.Proto, method)
	}
	for header, want := range map[string]string{
		"Content-Type":         "application/grpc",
		"Te":                   "trailers",
		"X-Modal-Token-Id":     "ak-test",
		"X-Modal-Token-Secret": "as-test",
		"X-Modal-Client-Type":  clientType,
	} {
		if got := r.Header.Get(header); got != want {
			t.Errorf("header %s is %q, want %q", header, got, want)
		}
	}
	body, _ := io.ReadAll(r.Body)
	if message, err := unframe(body); err != nil || len(message) != 0 {
		t.Errorf("request body %v, want one empty message: %v", body, err)
	}
}
