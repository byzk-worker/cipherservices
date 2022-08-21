package cipherservices

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/byzk-worker/cipherservices/pb"
	"google.golang.org/grpc"
	"sync"
)

var (
	esciOid    = []byte{0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75}
	esciOidLen = 8
)

const (
	ServerCertTypeCa      int32 = 0
	ServerCertTypeSign          = 2
	ServerCertTypeEnv           = 1
	ServerCertTypeRsaCa         = 0x10000
	ServerCertTypeRsaSign       = 0x10002
	ServerCertTypeRsaEnv        = 0x10001
	ServerCertTypeEccCa         = 0x100000
	ServerCertTypeEccSign       = 0x100002
	ServerCertTypeEccEnv        = 0x100001
)

const (
	OutFlagTypeHex             = "0x000000"
	OutFlagTypeHex2            = "0x100000"
	OutFlagTypeBase64          = "0x400000"
	OutFlagTypeBase64WithSpace = "0x410000"
)

const (
	P7FlagHaveSrcData  = "1"
	P7FlagHaveSignCert = "2"
	P7FlagHaveSignTime = "3"
	P7FlagDataIsHash   = "0x10"
)

const (
	KeyFlagTypeDefault   = "0"
	KeyFlagTypeEncKey    = "1"
	KeyFlagTypePubKey    = "2"
	KeyFlagTypeCertNoHex = "0x60"
	KeyFlagTypeUserFlag  = "0x50"
	KeyFlagTypeOutCert   = "0x20"
	KeyFlagTypeOutPub    = "0x40"
)

type CipherClientRpcService struct {
	Dial    *grpc.ClientConn
	c       pb.SecurityServiceClient
	Context func() (context.Context, error)
	stream  pb.SecurityService_SecurityStreamClient
	sync.Mutex
}

func NewCipherClientRpcService(host string, ctx func() (context.Context, error)) *CipherClientRpcService {
	dial, _ := grpc.Dial(host, grpc.WithInsecure())
	client := pb.NewSecurityServiceClient(dial)
	return &CipherClientRpcService{
		Dial:    dial,
		c:       client,
		Context: ctx,
	}
}

func NewCipherClientRpcServiceWithDial(dial *grpc.ClientConn, ctx func() (context.Context, error)) *CipherClientRpcService {
	client := pb.NewSecurityServiceClient(dial)
	return &CipherClientRpcService{
		Dial:    dial,
		c:       client,
		Context: ctx,
	}
}

// OpenDevice 打开设备
func (this *CipherClientRpcService) OpenDevice() *CipherError {
	return this.OpenDeviceWithConnectionTypeAndContainer(pb.ConnectionTypeEnum_DEFAULT, "")
}

// OpenDeviceWithConnectionTypeAndContainer 打开设备传入连接类型与容器号
func (this *CipherClientRpcService) OpenDeviceWithConnectionTypeAndContainer(connectionType pb.ConnectionTypeEnum, containerName string) *CipherError {
	this.Lock()
	defer this.Unlock()
	if this.stream != nil {
		_ = this.stream.CloseSend()
		this.stream = nil
	}

	ctx, err := this.Context()
	if err != nil {
		return NewCipherErr(err, -9, "获取context失败")
	}

	securityStream, err := this.c.SecurityStream(ctx)
	if err != nil {
		return NewCipherErrWithGrpcErr(err)
	}
	if err = securityStream.Send(&pb.SecurityReq{
		Operation:      pb.OperationEnum_CREATE_CONNECTION,
		ConnectionType: connectionType,
		Container:      containerName,
	}); err != nil {
		_ = securityStream.CloseSend()
		this.stream = nil
		return NewCipherErrWithGrpcErr(err)
	}
	recv, err := securityStream.Recv()
	if err != nil {
		return NewCipherErrWithGrpcErr(err)
	}

	if recv.GetErrNo() != 0 {
		_ = securityStream.CloseSend()
		this.stream = nil
		return NewCipherErrWithErrCode(errors.New(recv.ErrMsg), recv.ErrNo)
	}

	this.stream = securityStream
	return nil
}

// CloseDevice 关闭设备
func (this *CipherClientRpcService) CloseDevice() *CipherError {
	this.Lock()
	defer this.Unlock()

	if this.stream == nil {
		return nil
	}

	if err := this.stream.CloseSend(); err != nil {
		return NewCipherErrWithGrpcErr(err)
	}

	this.stream = nil
	return nil
}

// SignP1 p1签名
func (this *CipherClientRpcService) SignP1(strData string, outFlag ...string) (string, *CipherError) {
	return this.SignP1WithSignAlg(strData, pb.SignAlgEnum_GBECSM3, outFlag...)
}

// SignP1WithSignAlg p1签名设置签名算法与输出标识
func (this *CipherClientRpcService) SignP1WithSignAlg(strData string, signAlg pb.SignAlgEnum, outFlag ...string) (string, *CipherError) {
	return this.SignP1WithAll(strData, pb.SrcDataTypeEnum_COMMON, signAlg, outFlag...)
}

// SignP1WithAll p1签名设置源数据类型和输出标识
func (this *CipherClientRpcService) SignP1WithAll(strData string, strDataType pb.SrcDataTypeEnum, signAlg pb.SignAlgEnum, outFlags ...string) (string, *CipherError) {
	this.Lock()
	defer this.Unlock()
	flag := ""
	if len(outFlags) > 0 {
		flag = outFlags[0]
	}

	if err := this.stream.Send(&pb.SecurityReq{
		Operation:   pb.OperationEnum_SIGN_P1,
		SrcData:     strData,
		SrcDataType: strDataType,
		SignAlg:     signAlg,
		Flage:       flag,
	}); err != nil {
		return "", NewCipherErrWithGrpcErr(err)
	}

	if recv, err := this.stream.Recv(); err != nil {
		return "", NewCipherErrWithGrpcErr(err)
	} else {
		if recv.GetErrNo() != 0 {
			return "", NewCipherErrWithErrCode(errors.New(recv.ErrMsg), recv.ErrNo)
		}
		return recv.StrResult, nil
	}

}

// VerifyP1 验证p1签名
func (this *CipherClientRpcService) VerifyP1(signedData string, srcData string, keyInfo string) *CipherError {
	return this.VerifyP1WithSignAlg(signedData, srcData, keyInfo, pb.SignAlgEnum_GBECSM3)
}

// VerifyP1WithSignAlg 验证p1签名设置签名算法
func (this *CipherClientRpcService) VerifyP1WithSignAlg(signedData string, srcData string, keyInfo string, signAlg pb.SignAlgEnum) *CipherError {
	return this.VerifyP1WithSrcType(signedData, srcData, pb.SrcDataTypeEnum_COMMON, keyInfo, signAlg)
}

// VerifyP1WithSrcType 验证p1签名设置源数据类型
func (this *CipherClientRpcService) VerifyP1WithSrcType(signedData string, srcData string, srcDataType pb.SrcDataTypeEnum, keyInfo string, signAlg pb.SignAlgEnum) *CipherError {
	return this.VerifyP1WithAll(signedData, srcData, srcDataType, keyInfo, KeyFlagTypeDefault, signAlg)
}

// VerifyP1WithAll 验证p1签名设置源数据类型和key类型
func (this *CipherClientRpcService) VerifyP1WithAll(signedData string, srcData string, srcDataType pb.SrcDataTypeEnum, keyInfo string, keyFlag string, signAlg pb.SignAlgEnum) *CipherError {
	this.Lock()
	defer this.Unlock()

	if err := this.stream.Send(&pb.SecurityReq{
		Operation:   pb.OperationEnum_VERIFY_P1,
		SignedData:  signedData,
		SrcData:     srcData,
		SrcDataType: srcDataType,
		Flage:       keyFlag,
		SignAlg:     signAlg,
		Cert:        keyInfo,
	}); err != nil {
		return NewCipherErrWithGrpcErr(err)
	}

	recv, err := this.stream.Recv()
	if err != nil {
		return NewCipherErrWithGrpcErr(err)
	}

	if recv.ErrNo != 0 {
		return NewCipherErrWithErrCode(errors.New(recv.ErrMsg), recv.ErrNo)
	}

	return nil
}

// SignP7 p7签名
func (this *CipherClientRpcService) SignP7(srcData string, outFlag ...string) (string, *CipherError) {
	return this.SignP7WithSignAlg(srcData, pb.SignAlgEnum_GBECSM3, outFlag...)
}

// SignP7WithSignAlg p7签名设置签名算法
func (this *CipherClientRpcService) SignP7WithSignAlg(srcData string, signAlg pb.SignAlgEnum, outFlag ...string) (string, *CipherError) {
	return this.SignP7WithSrcTypeAndSignAlg(srcData, pb.SrcDataTypeEnum_COMMON, signAlg, outFlag...)
}

// SignP7WithSrcTypeAndSignAlg p7签名设置源数据类型和签名算法
func (this *CipherClientRpcService) SignP7WithSrcTypeAndSignAlg(srcData string, srcDataType pb.SrcDataTypeEnum, signAlg pb.SignAlgEnum, outFlag ...string) (string, *CipherError) {
	return this.SignP7WithAll(srcData, srcDataType, signAlg, "", outFlag...)
}

// SignP7WithAll p7签名外设所有参数
func (this *CipherClientRpcService) SignP7WithAll(srcData string, srcDataType pb.SrcDataTypeEnum, signAlg pb.SignAlgEnum, signTime string, outFlags ...string) (string, *CipherError) {
	this.Lock()
	defer this.Unlock()
	flag := ""
	if len(outFlags) > 0 {
		flag = outFlags[0]
	}

	if err := this.stream.Send(&pb.SecurityReq{
		Operation:   pb.OperationEnum_SIGN_P7,
		SrcData:     srcData,
		SrcDataType: srcDataType,
		SignAlg:     signAlg,
		SignTime:    signTime,
		Flage:       flag,
	}); err != nil {
		return "", NewCipherErrWithGrpcErr(err)
	}

	recv, err := this.stream.Recv()
	if err != nil {
		return "", NewCipherErrWithGrpcErr(err)
	}

	if recv.GetErrNo() != 0 {
		return "", NewCipherErrWithErrCode(errors.New(recv.ErrMsg), recv.ErrNo)
	}
	return recv.StrResult, nil
}

// VerifyP7 P7验签
func (this *CipherClientRpcService) VerifyP7(signedData string, srcData string, flags ...string) *CipherError {
	return this.VerifyP7WithAll(signedData, srcData, pb.SrcDataTypeEnum_COMMON, "", flags...)
}

// VerifyP7WithCert 验证P7并设置证书
func (this *CipherClientRpcService) VerifyP7WithCert(signedData string, srcData string, cert string, flags ...string) *CipherError {
	return this.VerifyP7WithAll(signedData, srcData, pb.SrcDataTypeEnum_COMMON, cert, flags...)
}

// VerifyP7WithSrcDataType 验证p7并设置源数据类型
func (this *CipherClientRpcService) VerifyP7WithSrcDataType(signedData string, srcData string, srcDtaType pb.SrcDataTypeEnum, flag ...string) *CipherError {
	return this.VerifyP7WithAll(signedData, srcData, srcDtaType, "", flag...)
}

// VerifyP7WithAll 验证p7并设置所有可以设置的参数
func (this *CipherClientRpcService) VerifyP7WithAll(signedData string, srcData string, srcDataType pb.SrcDataTypeEnum, cert string, flags ...string) *CipherError {
	this.Lock()
	defer this.Unlock()

	flag := ""
	if len(flags) > 0 {
		flag = flags[0]
	}

	if err := this.stream.Send(&pb.SecurityReq{
		Operation:   pb.OperationEnum_VERIFY_P7,
		SrcData:     srcData,
		SrcDataType: srcDataType,
		SignedData:  signedData,
		Cert:        cert,
		Flage:       flag,
	}); err != nil {
		return NewCipherErrWithGrpcErr(err)
	}

	recv, err := this.stream.Recv()
	if err != nil {
		return NewCipherErrWithGrpcErr(err)
	}
	if recv.ErrNo != 0 {
		return NewCipherErrWithErrCode(errors.New(recv.ErrMsg), recv.ErrNo)
	}
	return nil
}

// ServerHello serverHello
func (this *CipherClientRpcService) ServerHello(clientHelloInfo string) (string, string, *CipherError) {
	this.Lock()
	defer this.Unlock()

	if err := this.stream.Send(&pb.SecurityReq{
		Operation:      pb.OperationEnum_SERVER_HELLO,
		StrClientHello: clientHelloInfo,
	}); err != nil {
		return "", "", NewCipherErrWithGrpcErr(err)
	}

	recv, err := this.stream.Recv()
	if err != nil {
		return "", "", NewCipherErrWithGrpcErr(err)
	}

	if recv.ErrNo != 0 {
		return "", "", NewCipherErrWithErrCode(errors.New(recv.ErrMsg), recv.ErrNo)
	}
	return recv.StrResult, recv.ServerRandom, nil
}

// ServerAuth server认证
func (this *CipherClientRpcService) ServerAuth(clientAuthInfo, serverRandom string) (string, *CipherError) {
	this.Lock()
	defer this.Unlock()

	if err := this.stream.Send(&pb.SecurityReq{
		Operation:       pb.OperationEnum_SERVER_AUTH,
		StrClientAuth:   clientAuthInfo,
		StrServerRandom: serverRandom,
	}); err != nil {
		return "", NewCipherErrWithGrpcErr(err)
	}

	recv, err := this.stream.Recv()
	if err != nil {
		return "", NewCipherErrWithGrpcErr(err)
	}

	if recv.ErrNo != 0 {
		return "", NewCipherErrWithErrCode(errors.New(recv.ErrMsg), recv.ErrNo)
	}

	return recv.StrResult, nil
}

// ReadCertInfo 读取证书内容
func (this *CipherClientRpcService) ReadCertInfo(certNo int32, outFlags ...string) (string, *CipherError) {
	this.Lock()
	defer this.Unlock()

	flag := ""
	if len(outFlags) > 0 {
		flag = outFlags[0]
	}

	if err := this.stream.Send(&pb.SecurityReq{
		Operation:  pb.OperationEnum_GET_CERT_INFO,
		CertInfoNo: certNo,
		Cert:       flag,
	}); err != nil {
		return "", NewCipherErrWithGrpcErr(err)
	}

	recv, err := this.stream.Recv()
	if err != nil {
		return "", NewCipherErrWithErrCode(errors.New(recv.ErrMsg), recv.ErrNo)
	}
	return recv.StrResult, nil
}

// GetServerCert 获取服务器端证书
func (this *CipherClientRpcService) GetServerCert(certNo int32, outFlags ...string) (string, *CipherError) {
	this.Lock()
	defer this.Unlock()

	flag := ""
	if len(outFlags) > 0 {
		flag = outFlags[0]
	}

	if err := this.stream.Send(&pb.SecurityReq{
		Operation: pb.OperationEnum_GET_SERVER_CERT,
		CertNo:    certNo,
		Flage:     flag,
	}); err != nil {
		return "", NewCipherErrWithGrpcErr(err)
	}

	recv, err := this.stream.Recv()
	if err != nil {
		return "", NewCipherErrWithGrpcErr(err)
	}

	if recv.GetErrNo() != 0 {
		return "", NewCipherErrWithErrCode(errors.New(recv.ErrMsg), recv.ErrNo)
	}

	return recv.StrResult, nil
}

// P1SignBase64ConvertSealSign base64格式的p1签名转换为电子签章sign
func (this *CipherClientRpcService) P1SignBase64ConvertSealSign(str string) (string, *CipherError) {
	decodeString, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", NewCipherErr(err, -1, "签名数据从base64转换为der失败")
	}
	sign, cipherError := this.P1SignConvertSealSign(decodeString)
	if cipherError != nil {
		return "", cipherError
	}

	return base64.StdEncoding.EncodeToString(sign), nil
}

// P1SignConvertSealSign P1签名转换为电子签章sign
func (this *CipherClientRpcService) P1SignConvertSealSign(signBytes []byte) ([]byte, *CipherError) {
	signLen := len(signBytes)

	if signLen == 64 {
		return signBytes, nil
	}

	if (signBytes[0] & 0xff) != 0x30 {
		return nil, NewCipherErrWithErrCode(errors.New("获取sig id失败"), 1)
	}

	off := 1
	length := 0

	result := make([]byte, 0, 64)
	this.getLenBeam(signBytes[off:], &length, &off)
	if off+length != signLen {
		if signBytes[off+length]&0xff != 0x03 {
			return nil, NewCipherErrWithErrCode(errors.New(""), 2)
		}

		off += length
		off += 1
		this.getLenBeam(signBytes[off:], &length, &off)
		if signBytes[off]&0xff != 0x00 {
			return nil, NewCipherErrWithErrCode(errors.New(""), 3)
		}

		off += length
		off += 1
		this.getLenBeam(signBytes[off:], &length, &off)
		if signBytes[off]&0xff != 0x02 {
			return nil, NewCipherErrWithErrCode(errors.New(""), 4)
		}

		if signBytes[off+1]&0xff == 0x20 {
			startPos := off + 2
			result = append(result, signBytes[startPos:startPos+32]...)
			off += 34
		} else if signBytes[off+1]&0xff == 0x21 {
			startPos := off + 3
			result = append(result, signBytes[startPos:startPos+32]...)
			off += 35
		}

		if signBytes[off]&0xff != 0x02 {
			return nil, NewCipherErrWithErrCode(errors.New(""), 5)
		}

		if signBytes[off+1]&0xff == 0x20 {
			startPos := off + 2
			result = append(result, signBytes[startPos:startPos+32]...)
			off += 34
		} else if signBytes[off+1]&0xff == 0x20 {
			startPos := off + 3
			result = append(result, signBytes[startPos:startPos+32]...)
			off += 35
		}

	} else {
		if signBytes[off]&0xff != 0x02 {
			return nil, NewCipherErrWithErrCode(errors.New(""), 7)
		}

		if signBytes[off+1]&0xff == 0x20 {
			startPos := off + 2
			result = append(result, signBytes[startPos:startPos+32]...)
			off += 34
		} else if signBytes[off+1]&0xff == 0x21 {
			startPos := off + 3
			result = append(result, signBytes[startPos:startPos+32]...)
			off += 35
		}

		if signBytes[off]&0xff != 0x02 {
			return nil, NewCipherErrWithErrCode(errors.New(""), 8)
		}

		if signBytes[off+1]&0xff == 0x20 {
			startPos := off + 2
			result = append(result, signBytes[startPos:startPos+32]...)
			off += 34
		} else if signBytes[off+1]&0xff == 0x21 {
			startPos := off + 3
			result = append(result, signBytes[startPos:startPos+32]...)
			off += 35
		}

	}

	if off != signLen {
		return nil, NewCipherErrWithErrCode(errors.New(""), 9)
	}

	return result, nil
}

// SealSignBase64ConvertP1Sign 电子签章base64格式签章转换p1
func (this *CipherClientRpcService) SealSignBase64ConvertP1Sign(str string) (string, *CipherError) {
	decodeString, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", NewCipherErrWithErrCode(errors.New("解码base64签名数据失败"), -1)
	}
	sign, cipherError := this.SealSignConvertP1Sign(decodeString)
	if cipherError != nil {
		return "", cipherError
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

// SealSignConvertP1Sign 电子签章签名转换为P1签名
func (this *CipherClientRpcService) SealSignConvertP1Sign(signBytes []byte) ([]byte, *CipherError) {
	return this.SealSignConvertP1SignWithHasSignId(false, signBytes)
}

// SealSignConvertP1SignWithHasSignId 电子签章sign转换为p1签名
func (this *CipherClientRpcService) SealSignConvertP1SignWithHasSignId(hasSigId bool, signBytes []byte) ([]byte, *CipherError) {
	var (
		temp    = make([]byte, 500, 500)
		tempLen = 0
		weedLen = 500

		outData = make([]byte, 500, 500)
		outLen  = 500

		signLen = 500

		err error
	)

	if hasSigId {
		tempLen = 500
		if err = this.encodeTvl(0x06, esciOid, esciOidLen, temp, &tempLen); err != nil {
			return nil, NewCipherErrWithErrCode(err, 1)
		}

		if err = this.encodeTvl(0x30, temp, tempLen, outData, &outLen); err != nil {
			return nil, NewCipherErrWithErrCode(err, 2)
		}
	}

	tempLen = 500
	if err = this.encodeTvl(0x02, signBytes[:32], 32, temp, &tempLen); err != nil {
		return nil, NewCipherErrWithErrCode(err, 3)
	}

	if err = this.encodeTvl(0x02, signBytes[32:], 32, temp[tempLen:], &weedLen); err != nil {
		return nil, NewCipherErrWithErrCode(err, 4)
	}

	tempLen += weedLen
	if hasSigId {
		if err = this.encodeTvl(0x30, temp, tempLen, signBytes, &signLen); err != nil {
			return nil, NewCipherErrWithErrCode(err, 5)
		}

		weedLen = 500
		if err = this.encodeTvl(0x03, signBytes, signLen, outData[outLen:], &weedLen); err != nil {
			return nil, NewCipherErrWithErrCode(err, 6)
		}

		outLen += weedLen

	} else {
		if err = this.encodeTvl(0x30, temp, tempLen, outData, &outLen); err != nil {
			return nil, NewCipherErrWithErrCode(err, 6)
		}

	}

	return outData[:outLen], nil
}

// encodeTvl 电子签章sign转换p1签名使用
func (this *CipherClientRpcService) encodeTvl(mTag uint8, input []byte, inputLen int, mValue []byte, mValueLen *int) error {
	var (
		i, j, l, sequenceLen int
		k                    = inputLen
	)

	if input == nil || inputLen == 0 {
		mValue[0] = mTag
		mValue[1] = 0
		*mValueLen = 2
		return nil
	}

	if mTag == 0x3 {
		k += 1
	}

	if mTag == 0x2 && input[0]&0x80 != 0 {
		k += 1
	}

	sequenceLen = this.testLen(k)
	j = sequenceLen + k
	if j > *mValueLen {
		return errors.New("")
	}

	i = 0
	mValue[i] = mTag & 0xff
	i += 1

	this.encodeSequence(mValue[i:], k, &l)
	i += l
	if k > inputLen {
		mValue[i] = 0
		i += 1
	}

	this.copyData2ByteSlice(mValue, input, i, inputLen)

	i += inputLen
	*mValueLen = i
	return nil

}

// encodeSequence 电子签章sign转换p1签名使用
func (this *CipherClientRpcService) encodeSequence(data []byte, baoLen int, step *int) {
	length := uint8(baoLen)
	i := this.testLen(int(length))
	j := 0

	switch i {
	case 2:
		data[j] = length
	case 3:
		data[j] = 0x81
		j += 1
		data[j] = length
	case 4:
		data[j] = 0x82
		j += 1
		data[j] = length >> 8
		j += 1
		data[j] = length & 0xff
	case 6:
		data[j] = 0x84
		j += 1
		data[j] = (length >> 24) & 0xff
		j += 1
		data[j] = (length >> 16) & 0xff
		j += 1
		data[j] = (length >> 8) & 0xff
		j += 1
		data[j] = length & 0xff
	}

	j += 1
	*step = j
}

// testLen 电子签章sign转换p1签名使用
func (this *CipherClientRpcService) testLen(in int) int {
	j := 0
	if in < 128 {
		j = 2
	} else if in < 256 {
		j = 3
	} else if in < 65536 {
		j = 4
	} else {
		j = 6
	}
	return j
}

// getLenBeam 转换电子签章sign使用的工具函数
func (this *CipherClientRpcService) getLenBeam(signBytes []byte, length, tag *int) {
	switch signBytes[0] & 0xff {
	case 0x81:
		*length = int(signBytes[1] & 0xff)
		*tag += 3
	case 0x82:
		*length = int((signBytes[2] & 0xff) + ((signBytes[1] & 0xff) << 8))
		*tag += 3
	case 0x84:
		*length = int(((signBytes[1] & 0xff) << 24) + ((signBytes[2] & 0xff) << 16) + ((signBytes[3] & 0xff) << 8) + (signBytes[4] & 0xff))
		*tag += 5
	default:
		*length = int(signBytes[0] & 0xff)
		*tag += 1
	}
}

// copyData2ByteSlice 电子签章sign转换p1签名使用
func (this *CipherClientRpcService) copyData2ByteSlice(srcBytes, destBytes []byte, srcStartPos, copyLen int) {

	destPost := srcStartPos + copyLen

	j := 0
	for i := srcStartPos; i < destPost; i++ {
		srcBytes[i] = destBytes[j]
		j += 1
	}
}
