# openssl用法详解
后续随着openssl版本更新，我将会继续补充。OpenSSL是一个安全套接字层密码库，其包括常用的密码算法、常用的密钥生成和证书封装管理功能及SSL协议，并提供了丰富的应用程序以供测试。
OpenSSL是一个开源的项目，其由三个部分组成：
openssl命令行工具；
libencrypt加密算法库；
libssl加密模块应用库；

这里主要学习下openssl命令工具的用法，openssl命令工具有两种运行模式：交换模式和批处理模式。直接输入openssl回车即可进入交互模式，而输入带命令选项的openssl命令则进行批处理模式。

官网：https://www.openssl.org/

官网文档：https://www.openssl.org/docs/manmaster/man1/

官方仓库 & download：https://github.com/openssl/openssl

## 常用方式

### 密码加密
```shell
openssl passwd [-crypt] [-1] [-apr1] [-salt string] [-in file] [-stdin] [-noverify] [-quiet] [-table] {password}
```
常用选项为：
```shell
-salt STRING：添加随机数；
-in FILE：对输入的文件内容进行加密；
-stdin：对标准输入的内容进行加密；
```
生成密码的hash值
```shell
[root@localhost ~]# openssl passwd -1 -salt 123456 PASSWORD
$1$123456$KP0rRo6agiZOiJz8GMOd00
```

### 生成随机数
一般都是用来做验证码的。
```shell
openssl rand [-out file] [-rand file(s)] [-base64] [-hex] num
```
选项
```shell
-base64：以base64编码格式输出；
-hex：使用十六进制编码格式；
-out FILE：将生成的内容保存在指定的文件中；
```
用法：
```shell
[root@localhost ~]# openssl rand  -base64  10
d0etSF7CA13hhg==
```

### 生成密钥对
```shell
openssl genrsa [-out filename] [-passout arg] [-des] [-des3] [-idea] [-f4] [-3] [-rand file(s)] [-engine id] [numbits]

```
常用选项：
```shell
-out FILENAME：将生成的私钥保存至指定的文件中；
[-des] [-des3] [-idea]：指定加密算法；
numbits：指明生成的私钥大小，默认是512；
```

用法结合umask, 生成私钥
```shell
[root@localhost ~]# (umask 077;openssl genrsa -out CA.key 4096)
Generating RSA private key, 4096 bit long modulus
.........................................................................................................................................++
.................................................................++
e is 65537 (0x10001)
[root@localhost ~]# ll CA.key 
-rw-------. 1 root root 3243 Feb  2 06:33 CA.key

```
再生成公钥
```shell
openssl rsa [-inform PEM|NET|DER] [-outform PEM|NET|DER] [-in filename] [-passin arg] [-out filename] [-passout arg] [-sgckey] [-des] [-des3] [-idea] [-text] [-noout] [-modulus] [-check] [-pubin] [-pubout] [-engine id]
```
选项
```shell
-in FILENAME：指明私钥文件的存放路径；
-out FILENAME：指明将公钥的保存路径；
-pubout：根据提供的私钥，从中提取出公钥；
```
例子
```shell
[root@localhost ~]# openssl rsa -pubout -in CA.key 
writing RSA key
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0r92sttB5yUOI3nE2nvj
PeTZaKkFw2f4cVy8x615afGDhw/XvfWqd2X3BqUy9pPyVoYLOrO0fvGWtx0zVy76
HZ/N3vkUdmzQlJahwKl+K2rVYl2U7fw+qO1UHzrvnNqe6p10KURwAsD1nhuRf/ra
SlxUuOPLNjyu5QeSjtoMuYbhk72M+ht+vNuZI8i2e9B6t6HzoHvnmxldjj+4tQje
BCxeWwaerb8iWZ8KiNDGtqu1X20EevvJY7sp7RzzUPT4EKrXQ6BUyl+VeodHiHxp
l/8gVdlDEYIyurjBwNJDl3I+ug+MZwB0BaPSqNdbgcQbwdM/E6SiBIKU366XkZ39
uDneIZEaZIe12k3MlxqvXyLrsHc2V4jNdK+BNF0bU8pd8Z0wJ7B+Fl/k1+4fD5hS
WLOziix36WrqWzgSgOAV4oEwZjLfBTWIPEcDLUO2LhrhHv4S9APi4FAIslu8QlHv
dkzHaG0e6zolsIAHa1wClTVwFFfmABmo2axpc3IAu9EQA4lLJwK5MiDlANHJBTY7
HXlAOGADgJXY3euiUB4oQ/WPcP2XPTmRQcYoey3hRETPbJd6heM6Rfx9TyCxjxeo
xStmZmhHKZZek+h14Q/hmaK946SkPcbbszL1WzK/STwpceDgnijMgStq6fIippLb
zaQiGXIq0SE8FGuYnCTYJPMCAwEAAQ==
-----END PUBLIC KEY-----

```

### 单向加密
用户密码，支付密码等重要的密码。一般来说具有唯一性，不可逆性，才是需要单向加密的。
```shell
openssl dgst [-md5|-md4|-md2|-sha1|-sha|-mdc2|-ripemd160|-dss1] [-c] [-d] [-hex] [-binary] [-out filename] [-sign filename] [-keyform arg] [-passin arg] [-verify filename] [-prverify filename] [-signature filename] [-hmac key] [file...]
```
其常用的选项为：
```
[-md5|-md4|-md2|-sha1|-sha|-mdc2|-ripemd160|-dss1]：指定一种单向加密算法；
-out FILENAME：将加密的内容保存到指定的文件中；
```
单向加密除了 openssl dgst 工具还有： md5sum，sha1sum，sha224sum，sha256sum ，sha384sum，sha512sum

生成指定文件的特征码
```shell
[root@localhost ~]# openssl dgst -md5 /tmp/fstab 
MD5(/tmp/fstab)= ef7b65e9d3200487dc06427934ce5c2d

[root@localhost ~]# md5sum /tmp/fstab 
ef7b65e9d3200487dc06427934ce5c2d  /tmp/fstab
```

字符串加密
```shell
[root@localhost ~]# echo hello,world | md5sum
757228086dc1e621e37bed30e0b73e17  -

[root@localhost ~]# echo hello,world | openssl dgst -md5
(stdin)= 757228086dc1e621e37bed30e0b73e1
```

### 对称加密算法
```shell
openssl enc -ciphername [-in filename] [-out filename] [-pass arg] [-e] [-d] [-a/-base64] [-A] [-k password] [-kfile filename] [-K key] [-iv IV] [-S salt] [-salt] [-nosalt] [-z] [-md] [-p] [-P] [-bufsize number] [-nopad] [-debug] [-none] [-engine id]
```
参数详解
```
-e：加密；
-d：解密；
-ciphername：ciphername为相应的对称加密算命名字，如-des3、-ase128、-cast、-blowfish等等。
-a/-base64：使用base-64位编码格式；
-salt：自动插入一个随机数作为文件内容加密，默认选项；
-in FILENAME：指定要加密的文件的存放路径；
-out FILENAME：指定加密后的文件的存放路径；
```
字符串加解密
```
[root@localhost ~]# echo "hello,world" | openssl enc -aes128 -e -a -salt
enter aes-128-cbc encryption password:
Verifying - enter aes-128-cbc encryption password:

U2FsdGVkX1/LT+Ri9pzjjS0FIGXJLNRc8ljvZJ3hf0M=
```
文件加解密
```
[root@localhost ~]# openssl enc -des3 -e -a -in /etc/fstab -out /tmp/fstab
enter des-ede3-cbc encryption password:
Verifying - enter des-ede3-cbc encryption password:

[root@localhost ~]# cat /tmp/fstab 
U2FsdGVkX1/pdsq5HUjsP5Kpqr378qnZSmH1j9a4KdasuG+6Jy+Mh0cRYA5IUuJ4
732mG1td6x2jvLq0JNpT+WcTFXoH30x1o6KDN6Kwyc26+uTjYb+cwf9ZhZWoEi4c
5Zh1h8S4PwKA9m/ebJAh97RSLuVWqPOsZDJ9w/zE3X0iKnb8nVNEkApB6OYjkV4s
....

[root@localhost ~]# openssl enc -d -des3 -a -salt -in /tmp/fstab 
enter des-ede3-cbc decryption password:
# /etc/fstab
# Created by anaconda on Sun Nov 19 02:26:36 2017
....
devpts                  /dev/pts                devpts  gid=5,mode=620  0 0
sysfs                   /sys                    sysfs   defaults        0 0
proc                    /proc                   proc    defaults        0 0
```

### 证书
这里就是我们需要了解的一个概念，ca签名和ssl证书之间的关系。

HTTPS即Hypertext Transfer Protocol Secure。由于其安全层使用的是TLS/SSL，因此HTTPS也可以称为HTTP over TLS或HTTP over SSL。
“HTTPS证书”又叫“SSL证书”、“SSL安全证书”、“SSL数字证书”，目前应用广泛，发展迅速。
SSL证书需要向国际公认的证书证书认证机构（简称CA，Certificate Authority）申请。

ca签名：Certificate Authority (CA) ，需要服务器向ca发送一个携带网站域名信息的请求，然后去ca上下载我们想要的公钥和证书。

域名：需要购买，但存在免费域名。

私钥：服务器端存放。

公钥，ssl证书：加密数据接口。

![](readme.assets/Pasted%20image%2020230417001532.png)

如果你只是想用SSL证书加固你的web服务器，但是并不需要CA签名的证书，那么 一个简单的方法是自己签发证书。
一种常见的你可以签发的类型是自签名证书 —— 使用自己的私钥签发的证书。 自签名证书可以向CA签发的证书一样用于加密数据，但是你的用户将收到提示 说明该证书不被其计算机或浏览器信息。因此，自签名证书只能在不需要向用户证明你的身份时使用，例如非生产环境或者非公开服务。（防止中间人攻击）
这里我们只需要自签名即可。

1.创建自签名证书。

为ca提供目录和文件: 
```shell
# mkdir -pv /etc/pki/CA/{certs,crl,newcerts}
# touch /etc/pki/CA/{serial,index.txt}
# echo 01 > /etc/pki/CA/serial

```

生成私钥：
```shell
[root@localhost ~]# (umask 077;openssl genrsa -out /etc/pki/CA/private/CAkey.pem 4096)
Generating RSA private key, 4096 bit long modulus
..............................++
.........................................................++
e is 65537 (0x10001)
[root@localhost ~]# ll /etc/pki/CA/private/CAkey.pem 
-rw-------. 1 root root 3243 Feb  2 07:10 /etc/pki/CA/private/CAkey.pem
```

自签名证书
```shell
[root@localhost CA]# openssl req -new -x509 -key /etc/pki/CA/private/cakey.pem  -out /etc/pki/CA/cacert.pem -days 3650
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]:CN
State or Province Name (full name) []:guangdong
Locality Name (eg, city) [Default City]:shenzhen  
Organization Name (eg, company) [Default Company Ltd]:magedu
Organizational Unit Name (eg, section) []:ops
Common Name (eg, your name or your server's hostname) []:ca.magedu.com
Email Address []:
[root@localhost CA]# 
[root@localhost CA]# 
[root@localhost CA]# ll 
total 20
-rw-r--r--. 1 root root 2025 Apr 17 02:14 cacert.pem
drwxr-xr-x. 2 root root 4096 May  9  2016 certs
drwxr-xr-x. 2 root root 4096 May  9  2016 crl
drwxr-xr-x. 2 root root 4096 May  9  2016 newcerts
drwx------. 2 root root 4096 Apr 17 02:12 private
```
其中命令, 用到子命令为req，其为证书请求及生成的工具，用到的选项解释为：
```shell
# openssl req -new -x509 -key /etc/pki/CA/private/cakey.pem -out /etc/pki/CA/cacert.pem -days 3650
```
用到的选项
```
-new：表示生成一个新的证书签署请求；
-x509：专用于生成CA自签证书；
-key：指定生成证书用到的私钥文件；
-out FILNAME：指定生成的证书的保存路径；
-days：指定证书的有效期限，单位为day，默认是365天；
```

2.颁发证书
在需要使用证书的主机上生成私钥（私钥文件位置无限制）
```shell
[root@localhost ~]# (umask;openssl genrsa -out httpd.key 4096)
0022
Generating RSA private key, 4096 bit long modulus
...................................................................................................................................................................................................++
............................................................++
e is 65537 (0x10001)
```
生成证书签署请求
```shell
[root@localhost ~]# openssl req -new -key httpd.key -out httpd.csr -days 3650
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]:CN       
State or Province Name (full name) []:guangdong
Locality Name (eg, city) [Default City]:shenzhen
Organization Name (eg, company) [Default Company Ltd]:magedu
Organizational Unit Name (eg, section) []:ops
Common Name (eg, your name or your server's hostname) []:web.magedu.com
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```
通过可靠的方式将证书签署请求发送给CA主机；
在CA服务器上签署证书后颁发证书
```shell
[root@localhost ~]# openssl ca -in httpd.csr -out /etc/pki/CA/certs/httpd.crt -days 365
Using configuration from /etc/pki/tls/openssl.cnf
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 1 (0x1)
        Validity
            Not Before: Apr 16 18:31:12 2018 GMT
            Not After : Apr 16 18:31:12 2019 GMT
        Subject:
            countryName               = CN
            stateOrProvinceName       = guangdong
            organizationName          = magedu
            organizationalUnitName    = ops
            commonName                = web.magedu.com
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                D2:A2:81:85:70:1B:12:A2:06:7E:F6:FB:32:7B:56:3B:7B:CB:A2:B2
            X509v3 Authority Key Identifier: 
                keyid:43:AE:6C:A2:6F:6E:E4:E1:C3:45:3E:1D:74:E6:94:89:50:25:0C:0A

Certificate is to be certified until Apr 16 18:31:12 2019 GMT (365 days)
Sign the certificate? [y/n]:y


1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Data Base Updated
```
上述命令用到了openssl命令的子命令CA，用于在CA服务器上签署或吊销证书。

查看证书信息：
```shell
[root@localhost ~]# openssl x509 -in /etc/pki/CA/certs/httpd.crt -noout -serial -dates -subject
serial=01
notBefore=Apr 16 18:31:12 2018 GMT
notAfter=Apr 16 18:31:12 2019 GMT
```

上述查看证书使用了openssl命令的子命令x509，其选项解释为：
```shell
-noout：不输出加密的证书内容；
-serial：输出证书序列号；
-dates：显示证书有效期的开始和终止时间；
-subject：输出证书的subject；
```
3.吊销证书
吊销证书的步骤通常为：
在使用证书的主机上获取要吊销的证书的serial和subject信息（使用查看证书的命令）
根据客户提交的serial和subject信息，对比本机数据库index.txt中存储的是否一致
如一致，则执行吊销证书的操作；
```shell
[root@localhost ~]# openssl ca -revoke /etc/pki/CA/newcerts/01.pem 
Using configuration from /etc/pki/tls/openssl.cnf
Revoking Certificate 01.
Data Base Updated
```
记的存储一下被吊销的证书编号
```shell
[root@localhost ~]# echo 01 > /etc/pki/CA/crlnumber
[root@localhost ~]# cat /etc/pki/CA/crlnumber
01
```
更新证书吊销列表
```shell
[root@localhost ~]# openssl ca -gencrl -out /etc/pki/CA/crl/ca.crl
Using configuration from /etc/pki/tls/openssl.cnf

```
-gencrl选项为根据/etc/pki/CA/index.txt文件中的信息生成crl文件。

查看crl文件
```shell
[root@localhost ~]# openssl crl -in /etc/pki/CA/crl/ca.crl -noout -text
Certificate Revocation List (CRL):
        Version 2 (0x1)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: /C=CN/ST=guangdong/L=shenzhen/O=magedu/OU=ops/CN=ca.magedu.com
        Last Update: Apr 16 18:54:35 2018 GMT
        Next Update: May 16 18:54:35 2018 GMT
        CRL extensions:
            X509v3 CRL Number: 
                1
Revoked Certificates:
    Serial Number: 01                 #吊销的证书serial
        Revocation Date: Apr 16 18:51:24 2018 GMT
    Signature Algorithm: sha1WithRSAEncryption

```

## 证书转换
我们之前接触的证书都是X.509格式，采用ASCII的PEM编码。还有其他 一些证书编码格式与容器类型。OpenSSL可以用来在众多不同类型之间 转换证书。这一部分主要介绍与证书格式转换相关的OpenSSL命令。

PEM转DER
可以将PEM编码的证书domain.crt转换为二进制DER编码的证书domain.der：
```shell
openssl x509 \
       -in domain.crt \
       -outform der -out domain.der
DER格式通常用于Java。
```

DER转PEM
同样，可以将DER编码的证书（domain.der）转换为PEM编码（domain.crt）：
```
openssl x509 \
       -inform der -in domain.der \
       -out domain.crt
```


PEM转PKCS7
可以将PEM证书（domain.crt和ca-chain.crt）添加到一个PKCS7（domain.p7b） 文件中：
```
openssl crl2pkcs7 -nocrl \
       -certfile domain.crt \
       -certfile ca-chain.crt \
       -out domain.p7b

```
使用-certfile选项指定要添加到PKCS7中的证书。PKCS7文件也被称为P7B，通常用于Java的Keystore和微软的IIS中保存证书的ASCII文件。

PKCS7转换为PEM
使用下面的命令将PKCS7文件（domain.p7b）转换为PEM文件：
```
openssl pkcs7 \
       -in domain.p7b \
       -print_certs -out domain.crt
```
如果PKCS7文件中包含多个证书，例如一个普通证书和一个中间CA证书，那么输出的 PEM文件中将包含所有的证书。****


PEM转换为PKCS12
可以将私钥文件（domain.key）和证书文件（domain.crt）组合起来生成PKCS12 文件（domain.pfx）：
```
openssl pkcs12 \
       -inkey domain.key \
       -in domain.crt \
       -export -out domain.pfx
```
上面的命令将提示你输入导出密码，可以留空不填。
PKCS12文件也被称为PFX文件，通常用于导入/导出微软IIS中的证书链。

PKCS12转换为PEM
也可以将PKCS12文件（domain.pfx）转换为PEM格式（domain.combined.crt）：
```
openssl pkcs12 \
       -in domain.pfx \
       -nodes -out domain.combined.crt
```
注意如果PKCS12文件中包含多个条目，例如证书及其私钥，那么生成的PEM 文件中将包含所有条目。

## 其他
还有些其他命令，慢慢补充了。

### 生成质数
```shell
$ openssl prime -generate -bits 2048 -hex
D668FDB1968891AE5D858E641B79C4BA18ABEF8C571CBE004EA5673FB3089961E4670681B794063592124D13FF553BBD5CCC81106A9E5F7D87370DD5DA6342B1DAC13CD2E584759CDEC3E76AEFB799848E48EA9C218F53FE3103E1081B8154AD41DDCB931175853FE3D433CECD886B4D94C211EAE01AE5EA93F8FBD6812A9DEF0308378EE963B3C39F80865BA0E1D957683F4ED77ADA9812091AA42E9A56F43C37185223FF9E3DD03C312E71DED072E5686873B3CA6F5F575C569FB0A10CFEA17D7FEB898A8A02549FF6E4B7A1FBCE78656D3DCF227318EEEF8E601C23AA32DF41A61F04D39FC752F70A809D636238340B7B929F0CDBA629F7DE6AAAC44D2BA5
```



