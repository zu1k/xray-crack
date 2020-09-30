# XRAY CRACKER

### 生成证书

使用 `-g username` 生成永久证书

```
# ./xray-cracker -g kali

证书已写入文件：xray-license.lic
```

### 破解 xray

目前 PubKey 是加密过的，加密算法很简单，但是那个函数是硬编码了几百个局部变量，替换一波后，两个一对进行加、减、异或等操作进行还原，看样子是用代码生成的加密函数代码然后编译的，如果花时间在这上面可能是个死局，因为可以在每一次编译前都重新生成一下代码

所以我选择从其他地方入手，很明显公钥是用来验证签名的，如此看来直接修改签名验证函数的返回值就行，golang 中 VerifyPSS 返回一个 err，如果`err==nil`就代表签名没问题，放在汇编里就是 `test 某寄存器` 然后 `setz`或`setnz`，改一下就行

我目前的能力还无法实现用程序对不同平台不同系统的二进制进行这个修改，还没学习怎么写，请大神们各显神通吧

## 破解效果

使用修改版 xray 和永久证书后，效果如下

```
# ./xray_linux_amd64 version

____  ___.________.    ____.   _____.___.
\   \/  /\_   __   \  /  _  \  \__  |   |
 \     /  |    _  _/ /  /_\  \  /   |   |
 /     \  |    |   \/    |    \ \____   |
\___/\  \ |____|   /\____|_   / / _____/
      \_/       \_/        \_/  \/

Version: 1.3.3/1d166d72/COMMUNITY-ADVANCED
Licensed to kali, license is valid until 2099-09-08 19:00:00

[INFO] 2020-09-29 00:20:20 [default:entry.go:122] set file descriptor limit to 10000
[INFO] 2020-09-29 00:20:20 [default:entry.go:157] loading config file from /home/kali/tools/scan/xray/config.yaml
[xray 1.3.3/1d166d72]
Build: [2020-09-17] [linux/amd64] [RELEASE/COMMUNITY-ADVANCED]
Compiler Version: go version go1.14.4 linux/amd64
License ID: 00000000000000000000000000000000
User Name: kali/00000000000000000000000000000000
Not Valid Before: 2020-06-11 12:00:00
Not Valid After: 2099-09-08 19:00:00

To show open source licenses, please use `osslicense` sub-command.
```
