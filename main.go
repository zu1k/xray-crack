package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
	"time"
)

var (
	originPubKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2K+PRbp/yumhaVnN92JS
GuQiwj7df64jHAo8MvXLWjYxU/yvqB4LbGty8ymKQy33qaDNpu9jgE2s8cXrtftm
/UcvwDb8sTqWXpDhxYhcvJM30agxz3/8VwNJ4JOvhk9Gn+msYIUz+gXZMBuUFKhi
BOd6C2Pro03GYwVTNjfwH/Y9C5EfPKIKNU/5t2cYo+TuOBk5ooP+NTaDzB6rb7fd
E5uuNnF21x3rdiI9rZcKPbuU97/0OWNcIUh5wfxPNWwcmjYmFuZcxk/7dOUD65s4
pTplCoMLOelacB0l442dM4w2xNpn+Yg7i/ujmg37F+VguCZJWnoyImdhp/raccNG
+wIDAQAB
-----END PUBLIC KEY-----`
	newPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtKvyFB24hIEVwMs4Xi00
FCW41tqELGYb7f63A/lAsBPVSOvGrQ5UzuKmttatQF/IDD9UcHqqbi+B80pydiGS
eKJOaly0GuX6hfDd51/uo7E44LyzJSSBhTc1vtbL5JbNcapnxo4P6rJ1Uh9V7y8z
pRvc1G2da00mQSYoIg/9ty21j4So+Fz/v37qhK50EEIeXGJZb4uz9I9iKCHaazjI
Lf293Gzvp7EFEpZkKrh2VktKaERh+jHmJqEe0z7U/sz0cCa9ohS+TF5nxmkAZBel
CwEMXjkjGnCWO3wXJoyrXMn1GY/ilNPDFT7rSZBKLEIi7PrBD1pVLGdq2zTboenV
6wIDAQAB
-----END PUBLIC KEY-----`
	newPrivateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtKvyFB24hIEVwMs4Xi00FCW41tqELGYb7f63A/lAsBPVSOvG
rQ5UzuKmttatQF/IDD9UcHqqbi+B80pydiGSeKJOaly0GuX6hfDd51/uo7E44Lyz
JSSBhTc1vtbL5JbNcapnxo4P6rJ1Uh9V7y8zpRvc1G2da00mQSYoIg/9ty21j4So
+Fz/v37qhK50EEIeXGJZb4uz9I9iKCHaazjILf293Gzvp7EFEpZkKrh2VktKaERh
+jHmJqEe0z7U/sz0cCa9ohS+TF5nxmkAZBelCwEMXjkjGnCWO3wXJoyrXMn1GY/i
lNPDFT7rSZBKLEIi7PrBD1pVLGdq2zTboenV6wIDAQABAoIBAQCu3PSxr4pVBLLP
JGFsFQggr9nUaS4f4rwJfswXlnibcratmzVxbTt7+TYuJF0OvyVZZToOm0q01lpJ
5LYfy6J+C2kl3I+csRXl6Rh8xgase+x252vj+Q86phLon/A7UBGLf8htDjYti4et
chK0KtUramozV9xSbBsoVwvk2+FOFdiLsc+B3PyuydB0Lvov5EDBtZJ1GbnyWk/3
c++aL+lkjQbIs11A4Nwp7hUdPmM/Va8VK+DqWxbFCIr6rli5d9VOE//EHJ7S7aPp
+fxV9gyv1d0WBRNktH2t8O2JVn90379/EgWuonSlRG+HrhqZKrXIKuIFJEUmGUjs
8qJNzoERAoGBAOLjiGbXuOQHkshDqdB4xF1b4rvCBrr881dBAOnYqSyEUWuUD3et
4qX/7GaxWlSU2IteB+r5FyfEpmqUNmKVsgLkGh3lgeTU0Mss2+2xIAODNXvba8MV
UIawpvDFnLN2HEY/d+LYycBjWDk+6B1+dGlPZIxXF+8HqGnlqyBNFjP/AoGBAMva
WVB02FK4oXa8APTtvuQ2MP67Q95WdhZXdy8CEWnwJaknSTE3dXJ9nZZmFgHt54lo
KjbGfIOSCLeCqXm3ZGs5HQr2kY/xJXDJga6uNh71w66/q/W2z+30FFzta6BjYE/8
3pB+P4vUUsp/vb3SkNfRKdcNrtoL29UYdXM7QG4VAoGAQqLw/MN+2fofchHtXf0a
LxE9lkd2EpUYIxhEXGn1xc1W3HGv2UaIuphfpgmQribJMqV7Tde6pUNsXQEKuAmf
Lpov0XgGnl6itAmIzlanQGDY5HedPr6T1/sqDKz9SPf3depOG6HwH0EOOEHxijgJ
mKRos48gyGNHY1LA38vEKaECgYEAmu8fRsknyOdOwMFvMLiphyWw40pM8OVh5uUf
TnkR5ySAWynitSdjelsCtNZuD5VTjtm+i9cbt5v8SA1k5X9/MQc9jaGNTIuJW0mr
6Km7tJgx29UNyzjgnAgQmfhQ/pvJDcIxHjz16z66lfG0slshfwYX+L0LkenFcRaf
3a7A72kCgYEAhSSGHVkCTGteSyKxhbMVqTlxQQQWZKv4b+usqss00CKgs3CAKL8H
Crds7fq96xVDVCvxJGYMKQzG61MBa+e1f8YSdhl5EY1IltlHkZstgts7avG6MP6A
xMNjyLp1b84s2VVXTpSFA7i6KEUhl4NjqhZTslJht5Dfiy2Mmvfk2so=
-----END RSA PRIVATE KEY-----`
	pre2Bytes     = []byte{0x00, 0x01}
	pre17Bytes, _ = hex.DecodeString("01710d238a47f02c748d11d1ed906b4e1f")
	aesKey        = []byte{0x12, 0x23, 0x45, 0x56, 0x00, 0x87, 0x36, 0x93, 0x23, 0x86, 0x64, 0x76, 0x78, 0x67, 0x78, 0x00}
	aesIv         = []byte{0x71, 0x0d, 0x23, 0x8a, 0x47, 0xf0, 0x2c, 0x74, 0x8d, 0x11, 0xd1, 0xed, 0x90, 0x6b, 0x4e, 0x1f}
)

func main() {
	//parseAlready("xray-license.lic")
	genNew()
}

func parseAlready(licenseFile string) {
	// 加载公钥
	pubKey := importPublicKey(originPubKeyPem)

	// 解析 xray-license.lic 文件
	licenseFileData, err := ioutil.ReadFile(licenseFile)
	if err != nil {
		panic(err.Error())
	}
	licenseString := string(licenseFileData)
	tmpStrings := strings.Split(licenseString, "\n")
	licenseString = ""
	for _, line := range tmpStrings {
		if !strings.HasPrefix(line, "#") && line != "" {
			licenseString += line
		}
	}
	//fmt.Println("your license:", licenseString)

	decode_data, err := base64.StdEncoding.DecodeString(licenseString)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("pre 17: %x\n", decode_data[:17])
	//fmt.Printf("pre 17: %x\n", pre17Bytes)

	// aes解密license
	// 总长度 487，前面17个字节是单独加上的，所以总共解密出 480个字节的数据
	aesDecData, err := Decrypt(decode_data[17:])
	if err != nil {
		panic(err)
	}
	//fmt.Printf("AES DEC: %x\n", aesDecData)
	//fmt.Println(string(aesDecData))

	// 后半部分是明文的json
	licensePlainJsonBytes := aesDecData[0x102:]
	//fmt.Println("license info json:", string(licensePlainJsonBytes))

	license := License{}
	err = json.Unmarshal([]byte(licensePlainJsonBytes), &license)
	if err != nil {
		panic(err)
	}
	//fmt.Println("license parsed:", license)

	// rsa 验证签名 pss
	sum := sha256.Sum256(licensePlainJsonBytes)
	//fmt.Println(sum)

	// rsa使用 sha256算法，对 aes解密后的数据第三个字节开始，到后面json明文前面为止是签名
	//fmt.Println("解析出来的签名：", aesDecData[2:0x102])

	err = rsa.VerifyPSS(pubKey, crypto.SHA256, sum[:], aesDecData[2:0x102], nil)
	if err != nil {
		fmt.Println(err.Error())
		//panic(err.Error())
	} else {
		fmt.Println("varify success")
	}
}

func genNew() {
	validTime, err := time.Parse("2006-01-02 15:04:05", "2099-01-01 00:00:00")

	license := License{
		LicenseId:      "ee2bf288bbbe829be29a49830f2c38ec",
		UserId:         "490517af5242801ed981b37ff6987c18",
		UserName:       "zu1k",
		Distribution:   "COMMUNITY-ADVANCED",
		NotValidBefore: 1591891200,
		NotValidAfter:  validTime.Unix(),
	}

	licensePlainJsonBytes, _ := json.Marshal(license)
	licensePlainJson := string(licensePlainJsonBytes)

	fmt.Println("明文license信息：", licensePlainJson)

	// rsa sign
	priKey := importPrivateKey(newPrivateKeyPem)
	//fmt.Println(priKey)
	//sha256sum
	sum := sha256.Sum256(licensePlainJsonBytes)
	signature, err := rsa.SignPSS(rand.Reader, priKey, crypto.SHA256, sum[:], nil)
	if err != nil {
		panic(err)
	}

	//fmt.Println("新签名", len(signature), signature)

	licenseInfoWithSign := append(signature, licensePlainJsonBytes...)
	aesEnc, err := Encrypt(append(pre2Bytes, licenseInfoWithSign...))
	if err != nil {
		panic(err)
	}
	//fmt.Println(aesEnc)

	allBytes := append(pre17Bytes, aesEnc...)

	// 增加前17个字节的不知道干啥用的信息
	licenseText := base64.StdEncoding.EncodeToString(allBytes)
	fmt.Println("你的新证书:\n", licenseText)
}

func Decrypt(decode_data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(aesKey)
	blockMode := cipher.NewCBCDecrypter(block, aesIv)
	origin_data := make([]byte, len(decode_data))
	blockMode.CryptBlocks(origin_data, decode_data)
	return unpad(origin_data), nil
}

func unpad(ciphertext []byte) []byte {
	length := len(ciphertext)
	//去掉最后一次的padding
	unpadding := int(ciphertext[length-1])
	return ciphertext[:(length - unpadding)]
}

func Encrypt(text []byte) ([]byte, error) {
	block, _ := aes.NewCipher(aesKey)
	blockSize := block.BlockSize()
	originData := pad(text, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, aesIv)
	crypted := make([]byte, len(originData))
	blockMode.CryptBlocks(crypted, originData)
	//fmt.Println(len(originData))
	return crypted, nil
}

func pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

type License struct {
	LicenseId      string `json:"license_id"`
	UserId         string `json:"user_id"`
	UserName       string `json:"user_name"`
	Distribution   string `json:"distribution"`
	NotValidBefore int64  `json:"not_valid_before"`
	NotValidAfter  int64  `json:"not_valid_after"`
}

func importPublicKey(key string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		panic("unable to decode publicKey to request")
	}

	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	return pub.(*rsa.PublicKey)
}

func importPrivateKey(key string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(key))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return privateKey
}
