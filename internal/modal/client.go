// Package modal reads a Modal workspace through Modal's API. The API is
// gRPC, so each call is an HTTP/2 POST through the client
// componentsdk.NewHTTPClient returns, with the request and response in
// gRPC's framing and the message types from Modal's Go SDK.
package modal

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/locktivity/epack/componentsdk"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// APIHost is Modal's API host, the only host the token is sent to.
const APIHost = "api.modal.com"

const servicePath = "https://" + APIHost + "/modal.client.ModalClient/"

// Operation names, one per API call. They count each call in the collector
// result and key the test kit's fault matrix and the trace map, so rename
// one only on purpose.
const (
	OpTokenInfo                  = "modal.token.info"
	OpListMembers                = "modal.members.list"
	OpListServiceUsers           = "modal.service_users.list"
	OpListProxyTokens            = "modal.proxy_tokens.list"
	OpListProxyTokenEnvironments = "modal.proxy_tokens.environments.list"
	OpListEnvironments           = "modal.environments.list"
	OpGetEnvironmentRoles        = "modal.environments.roles.get"
	OpListSecrets                = "modal.secrets.list"
	OpListApps                   = "modal.apps.list"
	OpGetAppInfo                 = "modal.apps.info.get"
)

// RoleManager is the workspace role, in Modal's terms, that listing members
// and listing service users need. A Member's token is refused. Both
// operations declare it, so a permission_denied gap names it.
const RoleManager = "Manager"

// permissions holds the workspace role each operation needs. Modal's docs
// name a role for listing members and listing service users. They name none
// for the other calls the collector makes.
var permissions = map[string]string{
	OpListMembers:      RoleManager,
	OpListServiceUsers: RoleManager,
}

// The request headers that carry the token. CredentialHeaders lists them for
// componentsdk.HTTPOptions, so they go only to APIHost.
const (
	headerTokenID     = "X-Modal-Token-Id"
	headerTokenSecret = "X-Modal-Token-Secret"
)

// CredentialHeaders are the headers the token travels in.
var CredentialHeaders = []string{headerTokenID, headerTokenSecret}

// Modal's API reads a client's type and version from every request. The
// collector sends what Modal's Go SDK sends, since it uses that SDK's
// message types.
var clientType = strconv.Itoa(int(pb.ClientType_CLIENT_TYPE_LIBMODAL_GO))

const clientVersion = "1.0.0"

const (
	maxResponseBytes = 32 << 20
	// The secrets list comes in pages of secretsPageSize, each before the
	// oldest secret of the page before, up to maxSecretPages pages.
	secretsPageSize = 100
	maxSecretPages  = 100
)

// Client reads one workspace: the one the token belongs to.
type Client struct {
	http        *http.Client
	tokenID     string
	tokenSecret string
}

// NewClient returns a client that reads the workspace of the token with ID
// tokenID and secret tokenSecret.
func NewClient(httpClient *http.Client, tokenID, tokenSecret string) *Client {
	return &Client{http: httpClient, tokenID: tokenID, tokenSecret: tokenSecret}
}

// TokenInfo reads the token's workspace and who the token belongs to. It is
// the collector's sign-in.
func (c *Client) TokenInfo(ctx context.Context) (*pb.TokenInfoGetResponse, error) {
	resp := &pb.TokenInfoGetResponse{}
	if err := c.call(ctx, OpTokenInfo, "TokenInfoGet", &pb.TokenInfoGetRequest{}, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ListMembers lists the workspace's members. Modal refuses a Member's token.
func (c *Client) ListMembers(ctx context.Context) ([]*pb.WorkspaceMembersListItem, error) {
	resp := &pb.WorkspaceMembersListResponse{}
	if err := c.call(ctx, OpListMembers, "WorkspaceMembersList", &emptypb.Empty{}, resp); err != nil {
		return nil, err
	}
	return resp.GetMembers(), nil
}

// ListServiceUsers lists the workspace's service users, which only the Team
// and Enterprise plans have. Modal refuses a Member's token.
func (c *Client) ListServiceUsers(ctx context.Context) ([]*pb.ServiceUser, error) {
	resp := &pb.ServiceUserListResponse{}
	if err := c.call(ctx, OpListServiceUsers, "ServiceUserList", &emptypb.Empty{}, resp); err != nil {
		return nil, err
	}
	return resp.GetServiceUsers(), nil
}

// ListProxyTokens lists the workspace's proxy auth tokens.
func (c *Client) ListProxyTokens(ctx context.Context) ([]*pb.WebhookToken, error) {
	resp := &pb.WebhookTokenListResponse{}
	if err := c.call(ctx, OpListProxyTokens, "WebhookTokenList", &emptypb.Empty{}, resp); err != nil {
		return nil, err
	}
	return resp.GetTokens(), nil
}

// ProxyTokenEnvironments lists the IDs of the environments a proxy auth
// token is limited to.
func (c *Client) ProxyTokenEnvironments(ctx context.Context, tokenID string) ([]string, error) {
	req := pb.WebhookTokenEnvironmentListRequest_builder{TokenId: tokenID}.Build()
	resp := &pb.WebhookTokenEnvironmentListResponse{}
	if err := c.call(ctx, OpListProxyTokenEnvironments, "WebhookTokenEnvironmentList", req, resp); err != nil {
		return nil, err
	}
	return resp.GetEnvironmentIds(), nil
}

// ListEnvironments lists the environments the token can see.
func (c *Client) ListEnvironments(ctx context.Context) ([]*pb.EnvironmentListItem, error) {
	resp := &pb.EnvironmentListResponse{}
	if err := c.call(ctx, OpListEnvironments, "EnvironmentList", &emptypb.Empty{}, resp); err != nil {
		return nil, err
	}
	return resp.GetItems(), nil
}

// EnvironmentRoles reads who holds which role in a restricted environment.
func (c *Client) EnvironmentRoles(ctx context.Context, environmentID string) (*pb.EnvironmentGetRolesResponse, error) {
	req := pb.EnvironmentGetRolesRequest_builder{EnvironmentId: environmentID}.Build()
	resp := &pb.EnvironmentGetRolesResponse{}
	if err := c.call(ctx, OpGetEnvironmentRoles, "EnvironmentGetRoles", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ListSecrets lists an environment's secrets, newest first, without their
// values.
func (c *Client) ListSecrets(ctx context.Context, environment string) ([]*pb.SecretListItem, error) {
	var all []*pb.SecretListItem
	var before float64
	for page := 0; page < maxSecretPages; page++ {
		pagination := pb.ListPagination_builder{MaxObjects: secretsPageSize}
		if before > 0 {
			pagination.CreatedBefore = before
		}
		req := pb.SecretListRequest_builder{EnvironmentName: environment, Pagination: pagination.Build()}.Build()
		resp := &pb.SecretListResponse{}
		if err := c.call(ctx, OpListSecrets, "SecretList", req, resp); err != nil {
			return nil, err
		}
		items := resp.GetItems()
		all = append(all, items...)
		if len(items) < secretsPageSize {
			return all, nil
		}
		oldest := createdAt(items[0])
		for _, item := range items[1:] {
			oldest = min(oldest, createdAt(item))
		}
		if oldest <= 0 || (before > 0 && oldest >= before) {
			return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: a full page of secrets ended where the page before it did", OpListSecrets))
		}
		before = oldest
	}
	return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: more than %d pages of secrets", OpListSecrets, maxSecretPages))
}

// SecretCreatedAt is when a secret was created, in seconds since the epoch.
func SecretCreatedAt(item *pb.SecretListItem) float64 {
	return createdAt(item)
}

func createdAt(item *pb.SecretListItem) float64 {
	if t := item.GetMetadata().GetCreationInfo().GetCreatedAt(); t > 0 {
		return t
	}
	return item.GetCreatedAt()
}

// ListApps lists an environment's apps: the deployed ones, and those running
// or stopped recently.
func (c *Client) ListApps(ctx context.Context, environment string) ([]*pb.AppListResponse_AppListItem, error) {
	req := pb.AppListRequest_builder{EnvironmentName: environment}.Build()
	resp := &pb.AppListResponse{}
	if err := c.call(ctx, OpListApps, "AppList", req, resp); err != nil {
		return nil, err
	}
	return resp.GetApps(), nil
}

// AppInfo reads an app's functions: which are web endpoints, whether each
// needs a proxy auth token, and which run on a schedule.
func (c *Client) AppInfo(ctx context.Context, appID string) (*pb.AppGetInfoResponse, error) {
	req := pb.AppGetInfoRequest_builder{AppId: appID}.Build()
	resp := &pb.AppGetInfoResponse{}
	if err := c.call(ctx, OpGetAppInfo, "AppGetInfo", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// call sends req to method and decodes the answer into resp. The calls are
// all reads, so each is safe to retry.
func (c *Client) call(ctx context.Context, op, method string, req, resp proto.Message) error {
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op, Safe: true, Permission: permissions[op]})
	payload, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, servicePath+method, bytes.NewReader(frame(payload)))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	httpReq.Header.Set("Content-Type", "application/grpc")
	httpReq.Header.Set("Te", "trailers")
	httpReq.Header.Set("X-Modal-Client-Type", clientType)
	httpReq.Header.Set("X-Modal-Client-Version", clientVersion)
	httpReq.Header.Set(headerTokenID, c.tokenID)
	httpReq.Header.Set(headerTokenSecret, c.tokenSecret)

	res, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return componentsdk.ResponseError(res, fmt.Errorf("%s: reading the response: %w", op, err))
	}
	if res.StatusCode != http.StatusOK {
		return componentsdk.ResponseError(res, componentsdk.CodeError(componentsdk.ClassifyResponse(res), fmt.Errorf("%s: HTTP %d", op, res.StatusCode)))
	}
	if status, ok := responseStatus(res); ok && status.Code != 0 {
		return componentsdk.ResponseError(res, componentsdk.CodeError(Code(status.Code), fmt.Errorf("%s: %w", op, status)))
	}
	if len(body) > maxResponseBytes {
		return componentsdk.ResponseError(res, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: the response is larger than %d bytes", op, maxResponseBytes)))
	}
	message, err := unframe(body)
	if err == nil {
		err = proto.Unmarshal(message, resp)
	}
	if err != nil {
		return componentsdk.ResponseError(res, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: decoding the response: %w", op, err)))
	}
	return nil
}

// frame prefixes a message with gRPC's flag byte, 0 for uncompressed, and
// its length.
func frame(message []byte) []byte {
	out := make([]byte, 5, 5+len(message))
	binary.BigEndian.PutUint32(out[1:], uint32(len(message)))
	return append(out, message...)
}

// unframe returns the one message a unary response holds.
func unframe(body []byte) ([]byte, error) {
	if len(body) < 5 {
		return nil, errors.New("the response holds no gRPC message")
	}
	if body[0] != 0 {
		return nil, errors.New("the response's message is compressed")
	}
	size := binary.BigEndian.Uint32(body[1:5])
	if uint64(size) != uint64(len(body)-5) {
		return nil, fmt.Errorf("the response's message is %d bytes, but its frame says %d", len(body)-5, size)
	}
	return body[5:], nil
}

// Status is the gRPC status Modal answered a call with.
type Status struct {
	Code    int
	Message string
}

func (s *Status) Error() string {
	if s.Message == "" {
		return StatusName(s.Code)
	}
	return StatusName(s.Code) + ": " + s.Message
}

// responseStatus reads the call's gRPC status: from the headers when Modal
// answered with an error alone, and otherwise from the trailers after the
// body. A replayed recording has no trailers, so a response with neither is
// read as a success.
func responseStatus(res *http.Response) (*Status, bool) {
	for _, h := range []http.Header{res.Header, res.Trailer} {
		raw := h.Get("Grpc-Status")
		if raw == "" {
			continue
		}
		code, err := strconv.Atoi(raw)
		if err != nil {
			return &Status{Code: codeUnknown, Message: "grpc-status " + raw}, true
		}
		message, err := url.PathUnescape(h.Get("Grpc-Message"))
		if err != nil {
			message = h.Get("Grpc-Message")
		}
		return &Status{Code: code, Message: message}, true
	}
	return nil, false
}

// Classify gives a response the code its gRPC status means, for
// componentsdk.HTTPOptions.ClassifyResponse. Modal sends an error with HTTP
// status 200 and the gRPC status in its headers, so the options set
// ClassifySuccess too.
func Classify(res *http.Response, _ []byte) (componentsdk.Code, bool) {
	status, ok := responseStatus(res)
	if !ok || status.Code == 0 {
		return "", false
	}
	return Code(status.Code), true
}

// VendorCode names a response's gRPC status, such as PERMISSION_DENIED, for
// componentsdk.HTTPOptions.VendorCode.
func VendorCode(res *http.Response, _ []byte) string {
	if status, ok := responseStatus(res); ok && status.Code != 0 {
		return StatusName(status.Code)
	}
	return ""
}

// gRPC's status codes, from google.golang.org/grpc/codes.
const (
	codeCanceled           = 1
	codeUnknown            = 2
	codeInvalidArgument    = 3
	codeDeadlineExceeded   = 4
	codeNotFound           = 5
	codeAlreadyExists      = 6
	codePermissionDenied   = 7
	codeResourceExhausted  = 8
	codeFailedPrecondition = 9
	codeAborted            = 10
	codeOutOfRange         = 11
	codeUnimplemented      = 12
	codeInternal           = 13
	codeUnavailable        = 14
	codeDataLoss           = 15
	codeUnauthenticated    = 16
)

var statusNames = map[int]string{
	0:                      "OK",
	codeCanceled:           "CANCELLED",
	codeUnknown:            "UNKNOWN",
	codeInvalidArgument:    "INVALID_ARGUMENT",
	codeDeadlineExceeded:   "DEADLINE_EXCEEDED",
	codeNotFound:           "NOT_FOUND",
	codeAlreadyExists:      "ALREADY_EXISTS",
	codePermissionDenied:   "PERMISSION_DENIED",
	codeResourceExhausted:  "RESOURCE_EXHAUSTED",
	codeFailedPrecondition: "FAILED_PRECONDITION",
	codeAborted:            "ABORTED",
	codeOutOfRange:         "OUT_OF_RANGE",
	codeUnimplemented:      "UNIMPLEMENTED",
	codeInternal:           "INTERNAL",
	codeUnavailable:        "UNAVAILABLE",
	codeDataLoss:           "DATA_LOSS",
	codeUnauthenticated:    "UNAUTHENTICATED",
}

// StatusName is a gRPC status code's name, such as PERMISSION_DENIED.
func StatusName(code int) string {
	if name, ok := statusNames[code]; ok {
		return name
	}
	return "STATUS_" + strconv.Itoa(code)
}

// Code is the collection code a gRPC status means.
func Code(status int) componentsdk.Code {
	switch status {
	case codeUnauthenticated:
		return componentsdk.CodeAuthFailed
	case codePermissionDenied:
		return componentsdk.CodePermissionDenied
	case codeResourceExhausted:
		return componentsdk.CodeRateLimited
	case codeDeadlineExceeded:
		return componentsdk.CodeTimeout
	case codeInvalidArgument, codeUnimplemented, codeOutOfRange:
		return componentsdk.CodeInternal
	case codeDataLoss:
		return componentsdk.CodeInvalidResponse
	default:
		return componentsdk.CodeVendorError
	}
}
