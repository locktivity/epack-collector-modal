package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"

	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// grpcMessages gives each operation's request and response types.
var grpcMessages = map[string][2]func() proto.Message{
	modal.OpTokenInfo:                  {func() proto.Message { return &pb.TokenInfoGetRequest{} }, func() proto.Message { return &pb.TokenInfoGetResponse{} }},
	modal.OpListMembers:                {func() proto.Message { return &emptypb.Empty{} }, func() proto.Message { return &pb.WorkspaceMembersListResponse{} }},
	modal.OpListServiceUsers:           {func() proto.Message { return &emptypb.Empty{} }, func() proto.Message { return &pb.ServiceUserListResponse{} }},
	modal.OpListProxyTokens:            {func() proto.Message { return &emptypb.Empty{} }, func() proto.Message { return &pb.WebhookTokenListResponse{} }},
	modal.OpListProxyTokenEnvironments: {func() proto.Message { return &pb.WebhookTokenEnvironmentListRequest{} }, func() proto.Message { return &pb.WebhookTokenEnvironmentListResponse{} }},
	modal.OpListEnvironments:           {func() proto.Message { return &emptypb.Empty{} }, func() proto.Message { return &pb.EnvironmentListResponse{} }},
	modal.OpGetEnvironmentRoles:        {func() proto.Message { return &pb.EnvironmentGetRolesRequest{} }, func() proto.Message { return &pb.EnvironmentGetRolesResponse{} }},
	modal.OpListSecrets:                {func() proto.Message { return &pb.SecretListRequest{} }, func() proto.Message { return &pb.SecretListResponse{} }},
	modal.OpListApps:                   {func() proto.Message { return &pb.AppListRequest{} }, func() proto.Message { return &pb.AppListResponse{} }},
	modal.OpGetAppInfo:                 {func() proto.Message { return &pb.AppGetInfoRequest{} }, func() proto.Message { return &pb.AppGetInfoResponse{} }},
}

// grpcCodec is the kit's collectortest.BodyCodec for Modal's API. It reads a
// gRPC body as JSON, through protojson, with the message type its operation
// sends or gets back, and declines any body that isn't gRPC.
type grpcCodec struct{}

func (grpcCodec) DecodeRequest(op string, header http.Header, body []byte) ([]byte, error) {
	return decodeGRPC(op, 0, header, body)
}

func (grpcCodec) DecodeResponse(op string, header http.Header, body []byte) ([]byte, error) {
	return decodeGRPC(op, 1, header, body)
}

func (grpcCodec) EncodeResponse(op string, _ http.Header, json []byte) ([]byte, error) {
	m, err := grpcMessage(op, 1)
	if err != nil {
		return nil, err
	}
	if err := protojson.Unmarshal(json, m); err != nil {
		return nil, err
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	frame := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(payload)))
	return append(frame, payload...), nil
}

func decodeGRPC(op string, side int, header http.Header, body []byte) ([]byte, error) {
	if !strings.HasPrefix(header.Get("Content-Type"), "application/grpc") {
		return nil, nil
	}
	m, err := grpcMessage(op, side)
	if err != nil {
		return nil, err
	}
	if len(body) < 5 || body[0] != 0 || uint64(binary.BigEndian.Uint32(body[1:5])) != uint64(len(body)-5) {
		return nil, errors.New("the body is not one uncompressed gRPC message")
	}
	if err := proto.Unmarshal(body[5:], m); err != nil {
		return nil, err
	}
	return protojson.Marshal(m)
}

func grpcMessage(op string, side int) (proto.Message, error) {
	types, ok := grpcMessages[op]
	if !ok {
		return nil, fmt.Errorf("no message types for %s", op)
	}
	return types[side](), nil
}
