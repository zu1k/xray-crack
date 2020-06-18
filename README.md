# XRAY CRACKER

前几天长亭官方有个活动，可以领2个月的xray社区高级版证书，正好趁这个机会逆向分析了一下xray的证书算法，写了一个证书生成器

因为xray证书用到了rsa算法，所以需要替换xray程序中的公钥，将该功能也集成在工具中了

相关算法分析文章后面有空再写，这里先放出写好的工具

## 工具使用

### 查看帮助

使用 `-h` 查看帮助

```
PS > .\xray-cracker -h
破解xray高级版证书，使用 -h 参数查看使用帮助

Usage of xray-cracker:
  -c string
        替换xray程序内置公钥，需要指定xray程序文件路径
  -g string
        生成一个永久license，需要指定用户名
  -p string
        解析官方证书，需要指定证书路径
```

### 生成证书

使用 `-g username` 生成永久证书

```
PS > .\xray-cracker -g "我叫啥"
破解xray高级版证书，使用 -h 参数查看使用帮助

证书已写入文件：xray-license.lic
```

### 破解xray

使用 `-c path-to-xray` 修改xray内置公钥

```
PS > .\xray-cracker -c .\xray_windows_amd64.exe
破解xray高级版证书，使用 -h 参数查看使用帮助

public key index: 16741321
文件写入成功： .\xray_windows_amd64.exe
```

> 工具虽然是windows平台下运行，但是照样可以破解其他平台xray  
> 目前xray最新版是1.0.0，现在全平台全版本通杀


## 破解效果

使用修改版xray和永久证书后，效果如下

```
PS > .\xray_windows_amd64.exe version

 __   __  _____              __     __
 \ \ / / |  __ \      /\     \ \   / /
  \ V /  | |__) |    /  \     \ \_/ /
   > <   |  _  /    / /\ \     \   /
  / . \  | | \ \   / ____ \     | |
 /_/ \_\ |_|  \_\ /_/    \_\    |_|


Version: 1.0.0/62161168/COMMUNITY-ADVANCED
Licensed to 我叫啥, license is valid until 2099-09-09 08:00:00

[xray 1.0.0/62161168]
Build: [2020-06-13] [windows/amd64] [RELEASE/COMMUNITY-ADVANCED]
Compiler Version: go version go1.14.1 linux/amd64
License ID: 00000000000000000000000000000000
User Name: 我叫啥/00000000000000000000000000000000
Not Valid Before: 2020-06-12 00:00:00
Not Valid After: 2099-09-09 08:00:00
```
