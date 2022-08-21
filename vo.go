package cipherservices

import (
	"google.golang.org/grpc/status"
	"strconv"
)

type CipherError struct {
	code   string
	msg    string
	srcErr error
}

func (this *CipherError) Err() error {
	return this.srcErr
}

func (this *CipherError) Code() string {
	return this.code
}

func (this *CipherError) Msg() string {
	return this.msg
}

func (this *CipherError) Error() string {
	return this.code + ": " + this.msg
}

func convertGrpcErr(err error) *status.Status {
	if err != nil {
		return nil
	}
	return status.Convert(err)
}

func NewCipherErr(err error, errCode int32, errMsg string) *CipherError {
	return &CipherError{
		srcErr: err,
		code:   strconv.Itoa(int(errCode)),
		msg:    errMsg,
	}
}

func NewCipherErrWithErrCode(err error, errCode int32) *CipherError {
	return &CipherError{
		srcErr: err,
		code:   strconv.Itoa(int(errCode)),
		msg:    err.Error(),
	}
}

func NewCipherErrWithGrpcErr(err error) *CipherError {
	grpcErr := convertGrpcErr(err)
	return &CipherError{
		srcErr: err,
		code:   grpcErr.Code().String(),
		msg:    grpcErr.Message(),
	}
}
