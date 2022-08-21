// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.5
// source: proxy-security.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// 连接设备枚举
type ConnectionTypeEnum int32

const (
	// 默认
	ConnectionTypeEnum_DEFAULT ConnectionTypeEnum = 0
	// 博雅签名服务器
	ConnectionTypeEnum_BK_SIGN_SERVER ConnectionTypeEnum = 1
	// 密码机服务器
	ConnectionTypeEnum_CIPHER_SERVER ConnectionTypeEnum = 2
	// 临时密钥服务器
	ConnectionTypeEnum_TEMP_SERVER ConnectionTypeEnum = 3
)

// Enum value maps for ConnectionTypeEnum.
var (
	ConnectionTypeEnum_name = map[int32]string{
		0: "DEFAULT",
		1: "BK_SIGN_SERVER",
		2: "CIPHER_SERVER",
		3: "TEMP_SERVER",
	}
	ConnectionTypeEnum_value = map[string]int32{
		"DEFAULT":        0,
		"BK_SIGN_SERVER": 1,
		"CIPHER_SERVER":  2,
		"TEMP_SERVER":    3,
	}
)

func (x ConnectionTypeEnum) Enum() *ConnectionTypeEnum {
	p := new(ConnectionTypeEnum)
	*p = x
	return p
}

func (x ConnectionTypeEnum) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ConnectionTypeEnum) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_security_proto_enumTypes[0].Descriptor()
}

func (ConnectionTypeEnum) Type() protoreflect.EnumType {
	return &file_proxy_security_proto_enumTypes[0]
}

func (x ConnectionTypeEnum) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ConnectionTypeEnum.Descriptor instead.
func (ConnectionTypeEnum) EnumDescriptor() ([]byte, []int) {
	return file_proxy_security_proto_rawDescGZIP(), []int{0}
}

// 操作枚举
type OperationEnum int32

const (
	// 空值
	OperationEnum_MULL OperationEnum = 0
	// 建立连接
	OperationEnum_CREATE_CONNECTION OperationEnum = 1
	// 关闭设备
	OperationEnum_CLOSE OperationEnum = 2
	// P1签名
	OperationEnum_SIGN_P1 OperationEnum = 3
	// p1验签
	OperationEnum_VERIFY_P1 OperationEnum = 4
	// P7签名
	OperationEnum_SIGN_P7 OperationEnum = 5
	// P7验签
	OperationEnum_VERIFY_P7 OperationEnum = 6
	// 制作数字信封
	OperationEnum_ENC_ENVELOPE OperationEnum = 7
	// 解数字信封
	OperationEnum_DEC_ENVELOPE OperationEnum = 8
	// 身份认证serverHello
	OperationEnum_SERVER_HELLO OperationEnum = 9
	// 身份认证serverAuth
	OperationEnum_SERVER_AUTH OperationEnum = 10
	// 读取服务器证书
	OperationEnum_GET_SERVER_CERT OperationEnum = 11
	// 获取证书索引项内容
	OperationEnum_GET_CERT_INFO OperationEnum = 12
	// 消息摘要
	OperationEnum_DIGEST_DATA OperationEnum = 13
)

// Enum value maps for OperationEnum.
var (
	OperationEnum_name = map[int32]string{
		0:  "MULL",
		1:  "CREATE_CONNECTION",
		2:  "CLOSE",
		3:  "SIGN_P1",
		4:  "VERIFY_P1",
		5:  "SIGN_P7",
		6:  "VERIFY_P7",
		7:  "ENC_ENVELOPE",
		8:  "DEC_ENVELOPE",
		9:  "SERVER_HELLO",
		10: "SERVER_AUTH",
		11: "GET_SERVER_CERT",
		12: "GET_CERT_INFO",
		13: "DIGEST_DATA",
	}
	OperationEnum_value = map[string]int32{
		"MULL":              0,
		"CREATE_CONNECTION": 1,
		"CLOSE":             2,
		"SIGN_P1":           3,
		"VERIFY_P1":         4,
		"SIGN_P7":           5,
		"VERIFY_P7":         6,
		"ENC_ENVELOPE":      7,
		"DEC_ENVELOPE":      8,
		"SERVER_HELLO":      9,
		"SERVER_AUTH":       10,
		"GET_SERVER_CERT":   11,
		"GET_CERT_INFO":     12,
		"DIGEST_DATA":       13,
	}
)

func (x OperationEnum) Enum() *OperationEnum {
	p := new(OperationEnum)
	*p = x
	return p
}

func (x OperationEnum) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OperationEnum) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_security_proto_enumTypes[1].Descriptor()
}

func (OperationEnum) Type() protoreflect.EnumType {
	return &file_proxy_security_proto_enumTypes[1]
}

func (x OperationEnum) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OperationEnum.Descriptor instead.
func (OperationEnum) EnumDescriptor() ([]byte, []int) {
	return file_proxy_security_proto_rawDescGZIP(), []int{1}
}

// HASH 算法枚举
type HashAlgEnum int32

const (
	HashAlgEnum_DEF_HASH_ALG HashAlgEnum = 0
	HashAlgEnum_SHA1         HashAlgEnum = 1
	HashAlgEnum_SHA2         HashAlgEnum = 2
	HashAlgEnum_GBSM3        HashAlgEnum = 3
)

// Enum value maps for HashAlgEnum.
var (
	HashAlgEnum_name = map[int32]string{
		0: "DEF_HASH_ALG",
		1: "SHA1",
		2: "SHA2",
		3: "GBSM3",
	}
	HashAlgEnum_value = map[string]int32{
		"DEF_HASH_ALG": 0,
		"SHA1":         1,
		"SHA2":         2,
		"GBSM3":        3,
	}
)

func (x HashAlgEnum) Enum() *HashAlgEnum {
	p := new(HashAlgEnum)
	*p = x
	return p
}

func (x HashAlgEnum) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HashAlgEnum) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_security_proto_enumTypes[2].Descriptor()
}

func (HashAlgEnum) Type() protoreflect.EnumType {
	return &file_proxy_security_proto_enumTypes[2]
}

func (x HashAlgEnum) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use HashAlgEnum.Descriptor instead.
func (HashAlgEnum) EnumDescriptor() ([]byte, []int) {
	return file_proxy_security_proto_rawDescGZIP(), []int{2}
}

// 加密算法枚举
type EncAlgEnum int32

const (
	// 默认加密算法
	EncAlgEnum_DEF_ENC_ALG EncAlgEnum = 0
	EncAlgEnum_SSF33       EncAlgEnum = 1
)

// Enum value maps for EncAlgEnum.
var (
	EncAlgEnum_name = map[int32]string{
		0: "DEF_ENC_ALG",
		1: "SSF33",
	}
	EncAlgEnum_value = map[string]int32{
		"DEF_ENC_ALG": 0,
		"SSF33":       1,
	}
)

func (x EncAlgEnum) Enum() *EncAlgEnum {
	p := new(EncAlgEnum)
	*p = x
	return p
}

func (x EncAlgEnum) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EncAlgEnum) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_security_proto_enumTypes[3].Descriptor()
}

func (EncAlgEnum) Type() protoreflect.EnumType {
	return &file_proxy_security_proto_enumTypes[3]
}

func (x EncAlgEnum) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EncAlgEnum.Descriptor instead.
func (EncAlgEnum) EnumDescriptor() ([]byte, []int) {
	return file_proxy_security_proto_rawDescGZIP(), []int{3}
}

// 签名算法枚举
type SignAlgEnum int32

const (
	// 默认签名算法
	SignAlgEnum_DEF_SIGN_ALG SignAlgEnum = 0
	// 使用SM3信息摘要算法和SM2签名算法
	SignAlgEnum_GBECSM3 SignAlgEnum = 1
	// 使用MD5信息摘要算法和RSA签名算法
	SignAlgEnum_MD5withRSA SignAlgEnum = 2
	// 使用SHA-1信息摘要算法和RSA签名算法
	SignAlgEnum_SHA1withRSA SignAlgEnum = 3
	// 使用SHA-256信息摘要算法和RSA签名算法
	SignAlgEnum_SHA2withRSA SignAlgEnum = 4
	// 制作数字信封时，要求数字信封中不包含签名
	SignAlgEnum_NULL SignAlgEnum = 5
)

// Enum value maps for SignAlgEnum.
var (
	SignAlgEnum_name = map[int32]string{
		0: "DEF_SIGN_ALG",
		1: "GBECSM3",
		2: "MD5withRSA",
		3: "SHA1withRSA",
		4: "SHA2withRSA",
		5: "NULL",
	}
	SignAlgEnum_value = map[string]int32{
		"DEF_SIGN_ALG": 0,
		"GBECSM3":      1,
		"MD5withRSA":   2,
		"SHA1withRSA":  3,
		"SHA2withRSA":  4,
		"NULL":         5,
	}
)

func (x SignAlgEnum) Enum() *SignAlgEnum {
	p := new(SignAlgEnum)
	*p = x
	return p
}

func (x SignAlgEnum) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SignAlgEnum) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_security_proto_enumTypes[4].Descriptor()
}

func (SignAlgEnum) Type() protoreflect.EnumType {
	return &file_proxy_security_proto_enumTypes[4]
}

func (x SignAlgEnum) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SignAlgEnum.Descriptor instead.
func (SignAlgEnum) EnumDescriptor() ([]byte, []int) {
	return file_proxy_security_proto_rawDescGZIP(), []int{4}
}

// 原数据格式枚举
type SrcDataTypeEnum int32

const (
	SrcDataTypeEnum_DEF_TYPE SrcDataTypeEnum = 0
	// 16进制字符串
	SrcDataTypeEnum_HEX SrcDataTypeEnum = 1
	// 普通字符串
	SrcDataTypeEnum_COMMON SrcDataTypeEnum = 2
)

// Enum value maps for SrcDataTypeEnum.
var (
	SrcDataTypeEnum_name = map[int32]string{
		0: "DEF_TYPE",
		1: "HEX",
		2: "COMMON",
	}
	SrcDataTypeEnum_value = map[string]int32{
		"DEF_TYPE": 0,
		"HEX":      1,
		"COMMON":   2,
	}
)

func (x SrcDataTypeEnum) Enum() *SrcDataTypeEnum {
	p := new(SrcDataTypeEnum)
	*p = x
	return p
}

func (x SrcDataTypeEnum) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SrcDataTypeEnum) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_security_proto_enumTypes[5].Descriptor()
}

func (SrcDataTypeEnum) Type() protoreflect.EnumType {
	return &file_proxy_security_proto_enumTypes[5]
}

func (x SrcDataTypeEnum) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SrcDataTypeEnum.Descriptor instead.
func (SrcDataTypeEnum) EnumDescriptor() ([]byte, []int) {
	return file_proxy_security_proto_rawDescGZIP(), []int{5}
}

// 请求实体
type SecurityReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 操作类型
	Operation OperationEnum `protobuf:"varint,1,opt,name=operation,proto3,enum=cn.bk.platform.dzqz.proto.proxy.security.OperationEnum" json:"operation,omitempty"`
	// 连接设备枚举
	ConnectionType ConnectionTypeEnum `protobuf:"varint,2,opt,name=connectionType,proto3,enum=cn.bk.platform.dzqz.proto.proxy.security.ConnectionTypeEnum" json:"connectionType,omitempty"`
	// 待操作原数据
	SrcData string `protobuf:"bytes,3,opt,name=srcData,proto3" json:"srcData,omitempty"`
	// 格式(p1验签公钥类型，输出格式类型)
	Flage string `protobuf:"bytes,4,opt,name=flage,proto3" json:"flage,omitempty"`
	// Hash算法
	HashAlg HashAlgEnum `protobuf:"varint,5,opt,name=hashAlg,proto3,enum=cn.bk.platform.dzqz.proto.proxy.security.HashAlgEnum" json:"hashAlg,omitempty"`
	// 原数据类型
	SrcDataType SrcDataTypeEnum `protobuf:"varint,6,opt,name=srcDataType,proto3,enum=cn.bk.platform.dzqz.proto.proxy.security.SrcDataTypeEnum" json:"srcDataType,omitempty"`
	// 签名算法
	SignAlg SignAlgEnum `protobuf:"varint,7,opt,name=signAlg,proto3,enum=cn.bk.platform.dzqz.proto.proxy.security.SignAlgEnum" json:"signAlg,omitempty"`
	// 证书(16进制或base64字符串)
	Cert string `protobuf:"bytes,8,opt,name=cert,proto3" json:"cert,omitempty"`
	// 待验证的签名数据
	SignedData string `protobuf:"bytes,9,opt,name=signedData,proto3" json:"signedData,omitempty"`
	// p7签名签名时间
	SignTime string `protobuf:"bytes,10,opt,name=signTime,proto3" json:"signTime,omitempty"`
	// 加密算法
	EncAlg EncAlgEnum `protobuf:"varint,11,opt,name=encAlg,proto3,enum=cn.bk.platform.dzqz.proto.proxy.security.EncAlgEnum" json:"encAlg,omitempty"`
	// 待解密的数字信封
	EnvelopedData string `protobuf:"bytes,12,opt,name=envelopedData,proto3" json:"envelopedData,omitempty"`
	// clientHello返回数据
	StrClientHello string `protobuf:"bytes,13,opt,name=strClientHello,proto3" json:"strClientHello,omitempty"`
	// clientauth返回数据
	StrClientAuth string `protobuf:"bytes,14,opt,name=strClientAuth,proto3" json:"strClientAuth,omitempty"`
	// serverHello时服务器产生的随机数
	StrServerRandom string `protobuf:"bytes,15,opt,name=strServerRandom,proto3" json:"strServerRandom,omitempty"`
	// 读取的证书号
	CertNo int32 `protobuf:"varint,16,opt,name=certNo,proto3" json:"certNo,omitempty"`
	// 证书索引项
	CertInfoNo int32 `protobuf:"varint,17,opt,name=certInfoNo,proto3" json:"certInfoNo,omitempty"`
	// 获取指定容器中证书使用者-容器号
	Container string `protobuf:"bytes,18,opt,name=container,proto3" json:"container,omitempty"`
	// 制作数字信封时接收者证书或接收ID或证书序列号
	StrRecipientInfo string `protobuf:"bytes,19,opt,name=strRecipientInfo,proto3" json:"strRecipientInfo,omitempty"`
	// 密码组件配置
	Config map[string]string `protobuf:"bytes,20,rep,name=config,proto3" json:"config,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *SecurityReq) Reset() {
	*x = SecurityReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_security_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SecurityReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SecurityReq) ProtoMessage() {}

func (x *SecurityReq) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_security_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SecurityReq.ProtoReflect.Descriptor instead.
func (*SecurityReq) Descriptor() ([]byte, []int) {
	return file_proxy_security_proto_rawDescGZIP(), []int{0}
}

func (x *SecurityReq) GetOperation() OperationEnum {
	if x != nil {
		return x.Operation
	}
	return OperationEnum_MULL
}

func (x *SecurityReq) GetConnectionType() ConnectionTypeEnum {
	if x != nil {
		return x.ConnectionType
	}
	return ConnectionTypeEnum_DEFAULT
}

func (x *SecurityReq) GetSrcData() string {
	if x != nil {
		return x.SrcData
	}
	return ""
}

func (x *SecurityReq) GetFlage() string {
	if x != nil {
		return x.Flage
	}
	return ""
}

func (x *SecurityReq) GetHashAlg() HashAlgEnum {
	if x != nil {
		return x.HashAlg
	}
	return HashAlgEnum_DEF_HASH_ALG
}

func (x *SecurityReq) GetSrcDataType() SrcDataTypeEnum {
	if x != nil {
		return x.SrcDataType
	}
	return SrcDataTypeEnum_DEF_TYPE
}

func (x *SecurityReq) GetSignAlg() SignAlgEnum {
	if x != nil {
		return x.SignAlg
	}
	return SignAlgEnum_DEF_SIGN_ALG
}

func (x *SecurityReq) GetCert() string {
	if x != nil {
		return x.Cert
	}
	return ""
}

func (x *SecurityReq) GetSignedData() string {
	if x != nil {
		return x.SignedData
	}
	return ""
}

func (x *SecurityReq) GetSignTime() string {
	if x != nil {
		return x.SignTime
	}
	return ""
}

func (x *SecurityReq) GetEncAlg() EncAlgEnum {
	if x != nil {
		return x.EncAlg
	}
	return EncAlgEnum_DEF_ENC_ALG
}

func (x *SecurityReq) GetEnvelopedData() string {
	if x != nil {
		return x.EnvelopedData
	}
	return ""
}

func (x *SecurityReq) GetStrClientHello() string {
	if x != nil {
		return x.StrClientHello
	}
	return ""
}

func (x *SecurityReq) GetStrClientAuth() string {
	if x != nil {
		return x.StrClientAuth
	}
	return ""
}

func (x *SecurityReq) GetStrServerRandom() string {
	if x != nil {
		return x.StrServerRandom
	}
	return ""
}

func (x *SecurityReq) GetCertNo() int32 {
	if x != nil {
		return x.CertNo
	}
	return 0
}

func (x *SecurityReq) GetCertInfoNo() int32 {
	if x != nil {
		return x.CertInfoNo
	}
	return 0
}

func (x *SecurityReq) GetContainer() string {
	if x != nil {
		return x.Container
	}
	return ""
}

func (x *SecurityReq) GetStrRecipientInfo() string {
	if x != nil {
		return x.StrRecipientInfo
	}
	return ""
}

func (x *SecurityReq) GetConfig() map[string]string {
	if x != nil {
		return x.Config
	}
	return nil
}

// 返回实体
type SecurityResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 状态码0正常 其他全是错误
	ErrNo int32 `protobuf:"varint,1,opt,name=errNo,proto3" json:"errNo,omitempty"`
	// 消息短语
	ErrMsg string `protobuf:"bytes,2,opt,name=errMsg,proto3" json:"errMsg,omitempty"`
	// 结果
	StrResult string `protobuf:"bytes,3,opt,name=strResult,proto3" json:"strResult,omitempty"`
	// serverHello产生的服务器随机数
	ServerRandom string `protobuf:"bytes,4,opt,name=serverRandom,proto3" json:"serverRandom,omitempty"`
}

func (x *SecurityResp) Reset() {
	*x = SecurityResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_security_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SecurityResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SecurityResp) ProtoMessage() {}

func (x *SecurityResp) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_security_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SecurityResp.ProtoReflect.Descriptor instead.
func (*SecurityResp) Descriptor() ([]byte, []int) {
	return file_proxy_security_proto_rawDescGZIP(), []int{1}
}

func (x *SecurityResp) GetErrNo() int32 {
	if x != nil {
		return x.ErrNo
	}
	return 0
}

func (x *SecurityResp) GetErrMsg() string {
	if x != nil {
		return x.ErrMsg
	}
	return ""
}

func (x *SecurityResp) GetStrResult() string {
	if x != nil {
		return x.StrResult
	}
	return ""
}

func (x *SecurityResp) GetServerRandom() string {
	if x != nil {
		return x.ServerRandom
	}
	return ""
}

var File_proxy_security_proto protoreflect.FileDescriptor

var file_proxy_security_proto_rawDesc = []byte{
	0x0a, 0x14, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x28, 0x63, 0x6e, 0x2e, 0x62, 0x6b, 0x2e, 0x70, 0x6c,
	0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x64, 0x7a, 0x71, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
	0x22, 0xcd, 0x08, 0x0a, 0x0b, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71,
	0x12, 0x55, 0x0a, 0x09, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x37, 0x2e, 0x63, 0x6e, 0x2e, 0x62, 0x6b, 0x2e, 0x70, 0x6c, 0x61, 0x74,
	0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x64, 0x7a, 0x71, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x4f,
	0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x6e, 0x75, 0x6d, 0x52, 0x09, 0x6f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x64, 0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x3c, 0x2e, 0x63, 0x6e, 0x2e, 0x62, 0x6b, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d,
	0x2e, 0x64, 0x7a, 0x71, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x45, 0x6e, 0x75, 0x6d, 0x52, 0x0e, 0x63,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x18, 0x0a,
	0x07, 0x73, 0x72, 0x63, 0x44, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x73, 0x72, 0x63, 0x44, 0x61, 0x74, 0x61, 0x12, 0x14, 0x0a, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x65,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x66, 0x6c, 0x61, 0x67, 0x65, 0x12, 0x4f, 0x0a,
	0x07, 0x68, 0x61, 0x73, 0x68, 0x41, 0x6c, 0x67, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x35,
	0x2e, 0x63, 0x6e, 0x2e, 0x62, 0x6b, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e,
	0x64, 0x7a, 0x71, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x48, 0x61, 0x73, 0x68, 0x41, 0x6c,
	0x67, 0x45, 0x6e, 0x75, 0x6d, 0x52, 0x07, 0x68, 0x61, 0x73, 0x68, 0x41, 0x6c, 0x67, 0x12, 0x5b,
	0x0a, 0x0b, 0x73, 0x72, 0x63, 0x44, 0x61, 0x74, 0x61, 0x54, 0x79, 0x70, 0x65, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x39, 0x2e, 0x63, 0x6e, 0x2e, 0x62, 0x6b, 0x2e, 0x70, 0x6c, 0x61, 0x74,
	0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x64, 0x7a, 0x71, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x53,
	0x72, 0x63, 0x44, 0x61, 0x74, 0x61, 0x54, 0x79, 0x70, 0x65, 0x45, 0x6e, 0x75, 0x6d, 0x52, 0x0b,
	0x73, 0x72, 0x63, 0x44, 0x61, 0x74, 0x61, 0x54, 0x79, 0x70, 0x65, 0x12, 0x4f, 0x0a, 0x07, 0x73,
	0x69, 0x67, 0x6e, 0x41, 0x6c, 0x67, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x35, 0x2e, 0x63,
	0x6e, 0x2e, 0x62, 0x6b, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x64, 0x7a,
	0x71, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73,
	0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x41, 0x6c, 0x67, 0x45,
	0x6e, 0x75, 0x6d, 0x52, 0x07, 0x73, 0x69, 0x67, 0x6e, 0x41, 0x6c, 0x67, 0x12, 0x12, 0x0a, 0x04,
	0x63, 0x65, 0x72, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x63, 0x65, 0x72, 0x74,
	0x12, 0x1e, 0x0a, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x44, 0x61, 0x74, 0x61, 0x18, 0x09,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x44, 0x61, 0x74, 0x61,
	0x12, 0x1a, 0x0a, 0x08, 0x73, 0x69, 0x67, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x73, 0x69, 0x67, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x4c, 0x0a, 0x06,
	0x65, 0x6e, 0x63, 0x41, 0x6c, 0x67, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x34, 0x2e, 0x63,
	0x6e, 0x2e, 0x62, 0x6b, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x64, 0x7a,
	0x71, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73,
	0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x45, 0x6e, 0x63, 0x41, 0x6c, 0x67, 0x45, 0x6e,
	0x75, 0x6d, 0x52, 0x06, 0x65, 0x6e, 0x63, 0x41, 0x6c, 0x67, 0x12, 0x24, 0x0a, 0x0d, 0x65, 0x6e,
	0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x64, 0x44, 0x61, 0x74, 0x61, 0x18, 0x0c, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0d, 0x65, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x64, 0x44, 0x61, 0x74, 0x61,
	0x12, 0x26, 0x0a, 0x0e, 0x73, 0x74, 0x72, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x48, 0x65, 0x6c,
	0x6c, 0x6f, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x73, 0x74, 0x72, 0x43, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x12, 0x24, 0x0a, 0x0d, 0x73, 0x74, 0x72, 0x43,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x74, 0x68, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0d, 0x73, 0x74, 0x72, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x74, 0x68, 0x12, 0x28,
	0x0a, 0x0f, 0x73, 0x74, 0x72, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x52, 0x61, 0x6e, 0x64, 0x6f,
	0x6d, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x73, 0x74, 0x72, 0x53, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x65, 0x72, 0x74,
	0x4e, 0x6f, 0x18, 0x10, 0x20, 0x01, 0x28, 0x05, 0x52, 0x06, 0x63, 0x65, 0x72, 0x74, 0x4e, 0x6f,
	0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x65, 0x72, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x4e, 0x6f, 0x18, 0x11,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x0a, 0x63, 0x65, 0x72, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x4e, 0x6f,
	0x12, 0x1c, 0x0a, 0x09, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x18, 0x12, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12, 0x2a,
	0x0a, 0x10, 0x73, 0x74, 0x72, 0x52, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x6e,
	0x66, 0x6f, 0x18, 0x13, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x73, 0x74, 0x72, 0x52, 0x65, 0x63,
	0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x59, 0x0a, 0x06, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x18, 0x14, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x41, 0x2e, 0x63, 0x6e, 0x2e,
	0x62, 0x6b, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x64, 0x7a, 0x71, 0x7a,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x65, 0x63,
	0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65,
	0x71, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x1a, 0x39, 0x0a, 0x0b, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x22, 0x7e, 0x0a, 0x0c, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70,
	0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x4e, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x05, 0x65, 0x72, 0x72, 0x4e, 0x6f, 0x12, 0x16, 0x0a, 0x06, 0x65, 0x72, 0x72, 0x4d, 0x73, 0x67,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x65, 0x72, 0x72, 0x4d, 0x73, 0x67, 0x12, 0x1c,
	0x0a, 0x09, 0x73, 0x74, 0x72, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x73, 0x74, 0x72, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x22, 0x0a, 0x0c,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0c, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d,
	0x2a, 0x59, 0x0a, 0x12, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79,
	0x70, 0x65, 0x45, 0x6e, 0x75, 0x6d, 0x12, 0x0b, 0x0a, 0x07, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c,
	0x54, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e, 0x42, 0x4b, 0x5f, 0x53, 0x49, 0x47, 0x4e, 0x5f, 0x53,
	0x45, 0x52, 0x56, 0x45, 0x52, 0x10, 0x01, 0x12, 0x11, 0x0a, 0x0d, 0x43, 0x49, 0x50, 0x48, 0x45,
	0x52, 0x5f, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x10, 0x02, 0x12, 0x0f, 0x0a, 0x0b, 0x54, 0x45,
	0x4d, 0x50, 0x5f, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x10, 0x03, 0x2a, 0xf3, 0x01, 0x0a, 0x0d,
	0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45, 0x6e, 0x75, 0x6d, 0x12, 0x08, 0x0a,
	0x04, 0x4d, 0x55, 0x4c, 0x4c, 0x10, 0x00, 0x12, 0x15, 0x0a, 0x11, 0x43, 0x52, 0x45, 0x41, 0x54,
	0x45, 0x5f, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x49, 0x4f, 0x4e, 0x10, 0x01, 0x12, 0x09,
	0x0a, 0x05, 0x43, 0x4c, 0x4f, 0x53, 0x45, 0x10, 0x02, 0x12, 0x0b, 0x0a, 0x07, 0x53, 0x49, 0x47,
	0x4e, 0x5f, 0x50, 0x31, 0x10, 0x03, 0x12, 0x0d, 0x0a, 0x09, 0x56, 0x45, 0x52, 0x49, 0x46, 0x59,
	0x5f, 0x50, 0x31, 0x10, 0x04, 0x12, 0x0b, 0x0a, 0x07, 0x53, 0x49, 0x47, 0x4e, 0x5f, 0x50, 0x37,
	0x10, 0x05, 0x12, 0x0d, 0x0a, 0x09, 0x56, 0x45, 0x52, 0x49, 0x46, 0x59, 0x5f, 0x50, 0x37, 0x10,
	0x06, 0x12, 0x10, 0x0a, 0x0c, 0x45, 0x4e, 0x43, 0x5f, 0x45, 0x4e, 0x56, 0x45, 0x4c, 0x4f, 0x50,
	0x45, 0x10, 0x07, 0x12, 0x10, 0x0a, 0x0c, 0x44, 0x45, 0x43, 0x5f, 0x45, 0x4e, 0x56, 0x45, 0x4c,
	0x4f, 0x50, 0x45, 0x10, 0x08, 0x12, 0x10, 0x0a, 0x0c, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x5f,
	0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x10, 0x09, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x45, 0x52, 0x56, 0x45,
	0x52, 0x5f, 0x41, 0x55, 0x54, 0x48, 0x10, 0x0a, 0x12, 0x13, 0x0a, 0x0f, 0x47, 0x45, 0x54, 0x5f,
	0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x5f, 0x43, 0x45, 0x52, 0x54, 0x10, 0x0b, 0x12, 0x11, 0x0a,
	0x0d, 0x47, 0x45, 0x54, 0x5f, 0x43, 0x45, 0x52, 0x54, 0x5f, 0x49, 0x4e, 0x46, 0x4f, 0x10, 0x0c,
	0x12, 0x0f, 0x0a, 0x0b, 0x44, 0x49, 0x47, 0x45, 0x53, 0x54, 0x5f, 0x44, 0x41, 0x54, 0x41, 0x10,
	0x0d, 0x2a, 0x3e, 0x0a, 0x0b, 0x48, 0x61, 0x73, 0x68, 0x41, 0x6c, 0x67, 0x45, 0x6e, 0x75, 0x6d,
	0x12, 0x10, 0x0a, 0x0c, 0x44, 0x45, 0x46, 0x5f, 0x48, 0x41, 0x53, 0x48, 0x5f, 0x41, 0x4c, 0x47,
	0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x53, 0x48, 0x41, 0x31, 0x10, 0x01, 0x12, 0x08, 0x0a, 0x04,
	0x53, 0x48, 0x41, 0x32, 0x10, 0x02, 0x12, 0x09, 0x0a, 0x05, 0x47, 0x42, 0x53, 0x4d, 0x33, 0x10,
	0x03, 0x2a, 0x28, 0x0a, 0x0a, 0x45, 0x6e, 0x63, 0x41, 0x6c, 0x67, 0x45, 0x6e, 0x75, 0x6d, 0x12,
	0x0f, 0x0a, 0x0b, 0x44, 0x45, 0x46, 0x5f, 0x45, 0x4e, 0x43, 0x5f, 0x41, 0x4c, 0x47, 0x10, 0x00,
	0x12, 0x09, 0x0a, 0x05, 0x53, 0x53, 0x46, 0x33, 0x33, 0x10, 0x01, 0x2a, 0x68, 0x0a, 0x0b, 0x53,
	0x69, 0x67, 0x6e, 0x41, 0x6c, 0x67, 0x45, 0x6e, 0x75, 0x6d, 0x12, 0x10, 0x0a, 0x0c, 0x44, 0x45,
	0x46, 0x5f, 0x53, 0x49, 0x47, 0x4e, 0x5f, 0x41, 0x4c, 0x47, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07,
	0x47, 0x42, 0x45, 0x43, 0x53, 0x4d, 0x33, 0x10, 0x01, 0x12, 0x0e, 0x0a, 0x0a, 0x4d, 0x44, 0x35,
	0x77, 0x69, 0x74, 0x68, 0x52, 0x53, 0x41, 0x10, 0x02, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x48, 0x41,
	0x31, 0x77, 0x69, 0x74, 0x68, 0x52, 0x53, 0x41, 0x10, 0x03, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x48,
	0x41, 0x32, 0x77, 0x69, 0x74, 0x68, 0x52, 0x53, 0x41, 0x10, 0x04, 0x12, 0x08, 0x0a, 0x04, 0x4e,
	0x55, 0x4c, 0x4c, 0x10, 0x05, 0x2a, 0x34, 0x0a, 0x0f, 0x53, 0x72, 0x63, 0x44, 0x61, 0x74, 0x61,
	0x54, 0x79, 0x70, 0x65, 0x45, 0x6e, 0x75, 0x6d, 0x12, 0x0c, 0x0a, 0x08, 0x44, 0x45, 0x46, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x10, 0x00, 0x12, 0x07, 0x0a, 0x03, 0x48, 0x45, 0x58, 0x10, 0x01, 0x12,
	0x0a, 0x0a, 0x06, 0x43, 0x4f, 0x4d, 0x4d, 0x4f, 0x4e, 0x10, 0x02, 0x32, 0x97, 0x01, 0x0a, 0x0f,
	0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12,
	0x83, 0x01, 0x0a, 0x0e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x53, 0x74, 0x72, 0x65,
	0x61, 0x6d, 0x12, 0x35, 0x2e, 0x63, 0x6e, 0x2e, 0x62, 0x6b, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66,
	0x6f, 0x72, 0x6d, 0x2e, 0x64, 0x7a, 0x71, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x65,
	0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x1a, 0x36, 0x2e, 0x63, 0x6e, 0x2e, 0x62,
	0x6b, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x2e, 0x64, 0x7a, 0x71, 0x7a, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x73, 0x65, 0x63, 0x75,
	0x72, 0x69, 0x74, 0x79, 0x2e, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73,
	0x70, 0x28, 0x01, 0x30, 0x01, 0x42, 0x0a, 0x50, 0x01, 0x5a, 0x06, 0x70, 0x62, 0x2f, 0x3b, 0x70,
	0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proxy_security_proto_rawDescOnce sync.Once
	file_proxy_security_proto_rawDescData = file_proxy_security_proto_rawDesc
)

func file_proxy_security_proto_rawDescGZIP() []byte {
	file_proxy_security_proto_rawDescOnce.Do(func() {
		file_proxy_security_proto_rawDescData = protoimpl.X.CompressGZIP(file_proxy_security_proto_rawDescData)
	})
	return file_proxy_security_proto_rawDescData
}

var file_proxy_security_proto_enumTypes = make([]protoimpl.EnumInfo, 6)
var file_proxy_security_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_proxy_security_proto_goTypes = []interface{}{
	(ConnectionTypeEnum)(0), // 0: cn.bk.platform.dzqz.proto.proxy.security.ConnectionTypeEnum
	(OperationEnum)(0),      // 1: cn.bk.platform.dzqz.proto.proxy.security.OperationEnum
	(HashAlgEnum)(0),        // 2: cn.bk.platform.dzqz.proto.proxy.security.HashAlgEnum
	(EncAlgEnum)(0),         // 3: cn.bk.platform.dzqz.proto.proxy.security.EncAlgEnum
	(SignAlgEnum)(0),        // 4: cn.bk.platform.dzqz.proto.proxy.security.SignAlgEnum
	(SrcDataTypeEnum)(0),    // 5: cn.bk.platform.dzqz.proto.proxy.security.SrcDataTypeEnum
	(*SecurityReq)(nil),     // 6: cn.bk.platform.dzqz.proto.proxy.security.SecurityReq
	(*SecurityResp)(nil),    // 7: cn.bk.platform.dzqz.proto.proxy.security.SecurityResp
	nil,                     // 8: cn.bk.platform.dzqz.proto.proxy.security.SecurityReq.ConfigEntry
}
var file_proxy_security_proto_depIdxs = []int32{
	1, // 0: cn.bk.platform.dzqz.proto.proxy.security.SecurityReq.operation:type_name -> cn.bk.platform.dzqz.proto.proxy.security.OperationEnum
	0, // 1: cn.bk.platform.dzqz.proto.proxy.security.SecurityReq.connectionType:type_name -> cn.bk.platform.dzqz.proto.proxy.security.ConnectionTypeEnum
	2, // 2: cn.bk.platform.dzqz.proto.proxy.security.SecurityReq.hashAlg:type_name -> cn.bk.platform.dzqz.proto.proxy.security.HashAlgEnum
	5, // 3: cn.bk.platform.dzqz.proto.proxy.security.SecurityReq.srcDataType:type_name -> cn.bk.platform.dzqz.proto.proxy.security.SrcDataTypeEnum
	4, // 4: cn.bk.platform.dzqz.proto.proxy.security.SecurityReq.signAlg:type_name -> cn.bk.platform.dzqz.proto.proxy.security.SignAlgEnum
	3, // 5: cn.bk.platform.dzqz.proto.proxy.security.SecurityReq.encAlg:type_name -> cn.bk.platform.dzqz.proto.proxy.security.EncAlgEnum
	8, // 6: cn.bk.platform.dzqz.proto.proxy.security.SecurityReq.config:type_name -> cn.bk.platform.dzqz.proto.proxy.security.SecurityReq.ConfigEntry
	6, // 7: cn.bk.platform.dzqz.proto.proxy.security.SecurityService.securityStream:input_type -> cn.bk.platform.dzqz.proto.proxy.security.SecurityReq
	7, // 8: cn.bk.platform.dzqz.proto.proxy.security.SecurityService.securityStream:output_type -> cn.bk.platform.dzqz.proto.proxy.security.SecurityResp
	8, // [8:9] is the sub-list for method output_type
	7, // [7:8] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_proxy_security_proto_init() }
func file_proxy_security_proto_init() {
	if File_proxy_security_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proxy_security_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SecurityReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proxy_security_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SecurityResp); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proxy_security_proto_rawDesc,
			NumEnums:      6,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proxy_security_proto_goTypes,
		DependencyIndexes: file_proxy_security_proto_depIdxs,
		EnumInfos:         file_proxy_security_proto_enumTypes,
		MessageInfos:      file_proxy_security_proto_msgTypes,
	}.Build()
	File_proxy_security_proto = out.File
	file_proxy_security_proto_rawDesc = nil
	file_proxy_security_proto_goTypes = nil
	file_proxy_security_proto_depIdxs = nil
}