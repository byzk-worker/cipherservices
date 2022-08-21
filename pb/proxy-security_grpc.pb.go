// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.5
// source: proxy-security.proto

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// SecurityServiceClient is the client API for SecurityService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SecurityServiceClient interface {
	SecurityStream(ctx context.Context, opts ...grpc.CallOption) (SecurityService_SecurityStreamClient, error)
}

type securityServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSecurityServiceClient(cc grpc.ClientConnInterface) SecurityServiceClient {
	return &securityServiceClient{cc}
}

func (c *securityServiceClient) SecurityStream(ctx context.Context, opts ...grpc.CallOption) (SecurityService_SecurityStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &SecurityService_ServiceDesc.Streams[0], "/cn.bk.platform.dzqz.proto.proxy.security.SecurityService/securityStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &securityServiceSecurityStreamClient{stream}
	return x, nil
}

type SecurityService_SecurityStreamClient interface {
	Send(*SecurityReq) error
	Recv() (*SecurityResp, error)
	grpc.ClientStream
}

type securityServiceSecurityStreamClient struct {
	grpc.ClientStream
}

func (x *securityServiceSecurityStreamClient) Send(m *SecurityReq) error {
	return x.ClientStream.SendMsg(m)
}

func (x *securityServiceSecurityStreamClient) Recv() (*SecurityResp, error) {
	m := new(SecurityResp)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// SecurityServiceServer is the server API for SecurityService service.
// All implementations must embed UnimplementedSecurityServiceServer
// for forward compatibility
type SecurityServiceServer interface {
	SecurityStream(SecurityService_SecurityStreamServer) error
	mustEmbedUnimplementedSecurityServiceServer()
}

// UnimplementedSecurityServiceServer must be embedded to have forward compatible implementations.
type UnimplementedSecurityServiceServer struct {
}

func (UnimplementedSecurityServiceServer) SecurityStream(SecurityService_SecurityStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method SecurityStream not implemented")
}
func (UnimplementedSecurityServiceServer) mustEmbedUnimplementedSecurityServiceServer() {}

// UnsafeSecurityServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SecurityServiceServer will
// result in compilation errors.
type UnsafeSecurityServiceServer interface {
	mustEmbedUnimplementedSecurityServiceServer()
}

func RegisterSecurityServiceServer(s grpc.ServiceRegistrar, srv SecurityServiceServer) {
	s.RegisterService(&SecurityService_ServiceDesc, srv)
}

func _SecurityService_SecurityStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(SecurityServiceServer).SecurityStream(&securityServiceSecurityStreamServer{stream})
}

type SecurityService_SecurityStreamServer interface {
	Send(*SecurityResp) error
	Recv() (*SecurityReq, error)
	grpc.ServerStream
}

type securityServiceSecurityStreamServer struct {
	grpc.ServerStream
}

func (x *securityServiceSecurityStreamServer) Send(m *SecurityResp) error {
	return x.ServerStream.SendMsg(m)
}

func (x *securityServiceSecurityStreamServer) Recv() (*SecurityReq, error) {
	m := new(SecurityReq)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// SecurityService_ServiceDesc is the grpc.ServiceDesc for SecurityService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SecurityService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "cn.bk.platform.dzqz.proto.proxy.security.SecurityService",
	HandlerType: (*SecurityServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "securityStream",
			Handler:       _SecurityService_SecurityStream_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "proxy-security.proto",
}