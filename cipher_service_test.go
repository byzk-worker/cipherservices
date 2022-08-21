package cipherservices

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"testing"
)

func TestCipherService(t *testing.T) {
	dial, _ := grpc.Dial("192.168.100.25:9094", grpc.WithInsecure())
	cipherService := NewCipherClientRpcServiceWithDial(dial, func() (context.Context, error) {
		return context.Background(), nil
	})
	defer func() {
		if err := cipherService.CloseDevice(); err != nil {
			t.Error("关闭设备失败 => ", err.Error())
		}
	}()
	if err := cipherService.OpenDevice(); err != nil {
		t.Error("打开设备错误 => ", err.Error())
		return
	}

	srcData := "我是中国人，I Love You !!!"
	signedData := ""
	if res, cipherError := cipherService.SignP1(srcData); cipherError != nil {
		t.Error("P1签名失败 => ", cipherError.Error())
		return
	} else {
		signedData = res
		fmt.Println("P1签名结果 => ", res)
	}

	serverCert, cipherError := cipherService.GetServerCert(ServerCertTypeEccSign)
	if cipherError != nil {
		t.Error("获取服务器ECC_Sign证书失败 => ", cipherError.Err())
		return
	}

	fmt.Println("获取到的服务器ECC_Sign证书 => ", serverCert)

	if cipherError = cipherService.VerifyP1(signedData, srcData, serverCert); cipherError != nil {
		t.Error("验证P1签名失败 => ", cipherError.Err())
		return
	}

	if signedData, cipherError = cipherService.SignP7(srcData); cipherError != nil {
		t.Error("P7签名失败 => ", cipherError.Error())
		return
	}

	fmt.Println("P7签名结果 => ", signedData)

	if cipherError = cipherService.VerifyP7(signedData, srcData); cipherError != nil {
		t.Error("验证P7签名失败 => ", cipherError.Error())
		return
	}

}

func BenchmarkCipherService(b *testing.B) {
	srcData := "我是中国人，I Love You !!!"
	dial, _ := grpc.Dial("192.168.100.25:9094", grpc.WithInsecure())
	cipherService := NewCipherClientRpcServiceWithDial(dial, func() (context.Context, error) {
		return context.Background(), nil
	})
	defer func() {
		if err := cipherService.CloseDevice(); err != nil {
			b.Error("关闭设备失败 => ", err.Error())
		}
	}()
	if err := cipherService.OpenDevice(); err != nil {
		b.Error("打开设备错误 => ", err.Error())
		return
	}
	for i := 0; i < b.N; i++ {
		signedData := ""
		if res, cipherError := cipherService.SignP1(srcData); cipherError != nil {
			b.Error("P1签名失败 => ", cipherError.Error())
			return
		} else {
			signedData = res
		}

		serverCert, cipherError := cipherService.GetServerCert(ServerCertTypeEccSign)
		if cipherError != nil {
			b.Error("获取服务器ECC_Sign证书失败 => ", cipherError.Err())
			return
		}

		if cipherError = cipherService.VerifyP1(signedData, srcData, serverCert); cipherError != nil {
			b.Error("验证P1签名失败 => ", cipherError.Err())
			return
		}
	}
}

func BenchmarkSignP7(b *testing.B) {
	dial, _ := grpc.Dial("192.168.100.25:9094", grpc.WithInsecure())
	cipherService := NewCipherClientRpcServiceWithDial(dial, func() (context.Context, error) {
		return context.Background(), nil
	})
	defer func() {
		if err := cipherService.CloseDevice(); err != nil {
			b.Error("关闭设备失败 => ", err.Error())
		}
	}()
	if err := cipherService.OpenDevice(); err != nil {
		b.Error("打开设备错误 => ", err.Error())
		return
	}

	srcData := "我是中国人，I Love You !!!"
	for i := 0; i < b.N; i++ {
		if _, cipherError := cipherService.SignP7(srcData); cipherError != nil {
			b.Error(cipherError.Err())
		}
	}
}

func TestCipherClientRpcService_P1SignBase64ConvertQzSign(t *testing.T) {
	p1SignData := "MEQCICxZ1zwnj3NLIzs298TpGF3Gf+X2AvTpms2I00q6ZGrKAiBZF7YhXaLEqnFnalwXgu/IffWnj7p6Js8P79NQWmbwsQ=="
	services := CipherClientRpcService{}
	sign, cipherError := services.P1SignBase64ConvertSealSign(p1SignData)
	if cipherError != nil {
		panic(cipherError)
	}
	fmt.Println(sign)
}

func TestCipherClientRpcService_QzSignBase64ConvertP1Sign(t *testing.T) {
	qzSign := "LFnXPCePc0sjOzb3xOkYXcZ/5fYC9OmazYjTSrpkaspZF7YhXaLEqnFnalwXgu/IffWnj7p6Js8P79NQWmbwsQ=="
	services := CipherClientRpcService{}
	sign, cipherError := services.SealSignBase64ConvertP1Sign(qzSign)
	if cipherError != nil {
		panic(cipherError)
	}
	fmt.Println(sign)
}

func TestQzSignConvert(t *testing.T) {
	signMap := map[string]string{
		"MEYCIQCp1UoItgZbhDxXNwmXueL6vcWmqVdMzgZlyYIPqkazvwIhAMLK7kldzH3c9o5N+hEV9gHfzF70ZL8SUhiGqQyj2vsf": "qdVKCLYGW4Q8VzcJl7ni+r3FpqlXTM4GZcmCD6pGs7/Cyu5JXcx93PaOTfoRFfYB38xe9GS/ElIYhqkMo9r7Hw==",
		"MEUCIGPBQXs/A2FEuCvaVFsw7i8yWy5pJwN4lOythuB2AcMHAiEAi8I4buFPDBJs0G0uKvpWhXQuI+gbbUK1quPeX7pNCpY=": "Y8FBez8DYUS4K9pUWzDuLzJbLmknA3iU7K2G4HYBwweLwjhu4U8MEmzQbS4q+laFdC4j6BttQrWq495fuk0Klg==",
		"MEUCIDo5zf6rldUjRHvYJam7dRbXOHIu8DIJO3Qkza/lwGJIAiEA4McZsMs9S6kqfYlqfQm7v4G/EyX6Po6iRl4gAFGVJbU=": "OjnN/quV1SNEe9glqbt1Ftc4ci7wMgk7dCTNr+XAYkjgxxmwyz1LqSp9iWp9Cbu/gb8TJfo+jqJGXiAAUZUltQ==",
		"MEYCIQD5efPRw7g/d/ADBuxipdhsotykS2nqk+ADi3jrmb1uvwIhAPEBAwTntPTNRbVa9uu5mlWOF/a3h69N3Hmd+C2HfLrV": "+Xnz0cO4P3fwAwbsYqXYbKLcpEtp6pPgA4t465m9br/xAQME57T0zUW1WvbruZpVjhf2t4evTdx5nfgth3y61Q==",
		"MEQCIGnDe/gxMGzmYNlkhUPkkjdttO70cJ+P8ufMaDsXBFXDAiAwFMnlQeWtKi8aUw1B9PbhWmMBEb9YkU7uFWvECCLYUw==": "acN7+DEwbOZg2WSFQ+SSN2207vRwn4/y58xoOxcEVcMwFMnlQeWtKi8aUw1B9PbhWmMBEb9YkU7uFWvECCLYUw==",
	}

	service := &CipherClientRpcService{}
	for k, v := range signMap {
		r, err := service.P1SignBase64ConvertSealSign(k)
		if err != nil {
			t.Error("p1签名转换电子签章签名失败 => ", err.Error())
		}

		if r != v {
			t.Error("p1签名转换之后的电子签章签名与预期不符")
		}

		r, err = service.SealSignBase64ConvertP1Sign(v)
		if err != nil {
			t.Error("电子签章签名转p1签名失败 => ", err.Error())
		}
		if r != k {
			t.Error("电子签章签名转换之后的p1签名与预期不符")
		}
	}

}
