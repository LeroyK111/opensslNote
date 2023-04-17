# openssl用法详解
后续随着openssl版本更新，我将会继续补充。

OpenSSL是一个安全套接字层密码库，其包括常用的密码算法、常用的密钥生成和证书封装管理功能及SSL协议，并提供了丰富的应用程序以供测试。
OpenSSL是一个开源的项目，其由三个部分组成：
openssl命令行工具；
libencrypt加密算法库；
libssl加密模块应用库；

这里主要学习下openssl命令工具的用法，openssl命令工具有两种运行模式：交换模式和批处理模式。直接输入openssl回车即可进入交互模式，而输入带命令选项的openssl命令则进行批处理模式。

官网：https://www.openssl.org/

官网文档：https://www.openssl.org/docs/manmaster/man1/

官方仓库 & download：https://github.com/openssl/openssl

## 常用方式

### 密码加密passwd
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

### 生成随机数rand
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


### 对称加密算法enc
OpenSSL一共提供了8种对称加密算法，且支持电子密码本模式（ECB）、加密分组链接模式（CBC）、加密反馈模式（CFB）和输出反馈模式（OFB）四种常用的分组密码加密模式。这里以AES128的ECB模式做演示。

```shell
openssl enc -ciphername [-in filename] [-out filename] [-pass arg] [-e] [-d] [-a/-base64] [-A] [-k password] [-kfile filename] [-K key] [-iv IV] [-S salt] [-salt] [-nosalt] [-z] [-md] [-p] [-P] [-bufsize number] [-nopad] [-debug] [-none] [-engine id]
```
参数详解
```
-e：加密；
-d：解密；
-debug：打印debug输出

-ciphername：ciphername为相应的对称加密算命名字，如-des3、-ase128、-cast、-blowfish等等。
-a/-base64：使用base-64位编码格式，解密；
-iv iv 偏移量
-k key 对称加密中使用到的密钥，如果不使用-k则会要求从键盘输入
-salt：自动插入一个随机数作为文件内容加密，默认选项；
-in FILENAME：指定要加密的文件的存放路径；
-out FILENAME：指定加密后的文件的存放路径；
-p：打印
-salt：随机加盐
-nosalt：取消加盐
-s：手动指定加盐的值
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

### 非对称加密
OpenSSL 一共实现了4种非对称加密算法，包括DH算法、RSA算法、DSA算法和椭圆曲线算法（EC）。DH算法一般用户密钥交换。RSA 算法既可以用于密钥交换，也可以用于数字签名，当然，如果你能够忍受其缓慢的速度，那么也可以用于数据加密。DSA算法则一般只用于数字签名， 这里主要演示 RSA 算法，需要使用DH算法的可以自行研究 pkey 指令集合。

#### genrsa指令
`genrsa`指令虽然已经被功能更加全面的`genpkey`指令取代，但是因为其相对简单，功能纯粹，可以作为学习`genpkey`的基础。另外，`genpkey` 中的一些更详细的功能在现阶段使用不到，使用`genrsa`直接生成私钥相对简单方便，容易掌握。其可选参数如下：

```shell
usage: genrsa [args] [numbits] 
-out file output the key to 'file'（输出的文件名） 
-passout arg output file pass phrase source（给输出的文件设置密码，此处不同于对称算法加密，对称算法是对私钥结果进行加密，这里是对文件加密） 
-f4 use F4 (0x10001) for the E value(使用65537作为E的值，E在RSA算法中使用场景为：1<e<φ(n) ，默认) 
-3use 3 for the E value(使用3作为E的值，非默认) 

// 以下为对称加密选项 
-des encrypt the generated key with DES incbc mode 
-des3 encrypt the generated key with DES in ede cbc mode (168 bit key) -aes128, -aes192, -aes256 encrypt PEM output with cbc aes 
-camellia128, -camellia192, -camellia256 encrypt PEM output with cbc camellia
```
`genrsa`接两个参数，第一个选项参数，第二个为rsa算法中的m值的长度，一般为1024，更高安全级别的位2048。其中，如果不设置对称加密的算法，则不会对私钥结果进行加密，如果不为空，则会要求输入对称算法中将要使用的秘钥，使用如下：

```shell
# 生成不加密的私钥
openssl genrsa -out private.pem 1024

# 生成私钥，使用对称算法进行加密
openssl genrsa -aes128 -out private.pem 1024
```

#### rsa指令
rsa功能比较多，可以对秘钥进行管理。其中最主要的功能就是从私钥中提取公钥、查看秘钥的结构信息，可以使用-help查看：
```shell
usage: rsa [options] 
-check 检测秘钥合法性 
-in file 输入的文件名 
-inform format 输入文件的格式 (DER, NET orPEM (default)) 
-modulus 打印 RSA 秘钥的modulus 
-out file 输出的文件名 
-outform format 输出文件的格式(DER, NET or PEM (default PEM)) 
-passin src 输入文件的密码 
-passout src 输出文件的密码 
-pubin 该指令说明输入的是公钥，默认为私钥 
-pubout 该指令说明需要输出公钥，默认输出私钥 
-sgckey what it is？ 
-text 打印信息
```

查看密钥信息
```shell
openssl rsa -in private.pem -text
```

从私钥中提取公钥
```shell
openssl rsa -in private.pem -pubout -out public.pem
```

给密钥添加/去除/修改对称加密的密码
```shell
// 为RSA密钥增加口令保护 
openssl rsa -in RSA.pem -des3 -passout pass:123456 -out E_RSA.pem 

// 为RSA密钥去除口令保护 
openssl rsa -in E_RSA.pem -passin pass:123456 -out P_RSA.pem 

// 修改加密算法为aes128，口令是123456
openssl rsa -in RSA.pem -passin pass:123456 -aes128 -passout pass:123456 -out E_RSA.pem

```

转换密钥格式
```shell
// 把pem格式转化成der格式，使用outform指定der格式 
openssl rsa -in RSA.pem -passin pass:123456 -des -passout pass:123456 -outform der -out rsa.der
```

#### rsautl指令
以上两个指令时生成和管理秘钥，而`rsautl`指令则和秘钥的具体使用有关，也就是如何使用 rsa 秘钥进行加密解密操作。
```shell
Usage: rsautl [options] 
// 输入文件(被加密/解密/签名)和输出文件 
-in file 被操作的文件 
-out file 操作完成后的输出文件 

// 输入的秘钥 
-inkey file 完成操作时使用到的秘钥 

// 集中填充方式 
-ssl use SSL v2 padding 
-raw use no padding-pkcs use PKCS #1 v1.5 padding (default) 
-oaep use PKCS#1 OAEP 

// 几种功能选项 
-sign 使用私钥签名 
-verify 使用公钥验签 
-encrypt 使用公钥加密，注意是公钥加密 
-decrypt 使用私钥解密，注意是私钥解密 
-passin arg 如果秘钥被对称加密过，则使用该选项提供对称加密所使用的秘钥 // 其他 
-keyform arg 说明私钥格式，默认PEM 
-pubin 说明输入的是公钥 
-certin 输入的是携带rsa公钥的证书 
-hexdump 16进制输出
```

使用公钥加密
```shell
openssl rsautl -encrypt -in plain.text -inkey public.pem -out encrypt.text
```

使用私钥解密
```shell
openssl rsautl -decrypt -in encrypt.text -inkey private.pem -out replain.text
```

使用私钥签名
```shell
openssl rsautl -sign -in plain.text -inkey private.pem -out signed.text
```

使用公钥验签
```shell
openssl rsautl -verify -in signed.text -pubin -inkey public.pem -out verify.text
```

### 新的非对称加密指令
`openssl`更新之后有一个`pkey`系列的三个指令`genpkey`、`pkey`、`pkeyutl`，和原先的`genrsa`、`rsa`、`rsautl`一一对应。

新的指令集只是在原油基础上对功能进行了合并和扩展，所以这些指令不作为本文重点，具体使用可以在`openssl genpkey -help`中查看，这里只演示最常使用的几个指令：

#### genpkey生成私钥
```shell
// 使用随机数长度为1024的rsa算法生成pem格式的私钥并输出到rsa_pri.key文件中，且在文件中打印私钥/公钥参数/结构的文本 
openssl genpkey -out rsa_pri.key -outform PEM -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -text
```

#### pkey从私钥中提取公钥
pkey命令处理公钥或私钥。它们可以在各种形式之间进行转换，并将其结构打印出来。其指令如下：
```shell
openssl pkey -in private.pem -pubout -out public.pem


-in file 输入文件，如果没有则标准输入 
-inform X 输入的格式 
-passin arg 输入文件的密码 
-outform X 输出格式(DER/PEM) 
-out file 输出的文件，如果没有则标准输出 
-passout arg 输出文件加密所使用的密码 
-pubin 默认是读入私钥，该选项指定读入公钥 
-pubout 默认情况下会输出私钥，使用此选项将会 输出公钥，用于从私钥生成公钥-text 打印公私钥结构信息
```

#### pkeyutl加密解密
```shell
// 公钥加密 openssl pkeyutl -encrypt -in plain.text -inkey public.pem -out encrypt.text // 私钥解密 openssl pkeyutl -decrypt -in encrypt.text -inkey private.pem -out decrypt.text
```

#### pkeyutl 签名和验签
```shell
openssl pkeyutl -sign -in plain.text -inkey private.pem -out signed.text 

openssl pkeyutl -verify -pubin -inkey public.pem -in plain.text -sigfile signed.text -out verify.text
```


### 摘要算法dgst
摘要算法常用于数字签名，数字签名严格意义上来讲分为两步：生成摘要和签名。首先使用摘要算法对原文计算摘要，然后使用签名者的私钥对摘要进行签名。

openssl中的哈希函数加密主要使用命令`dgst`，也可以直接使用对应算法指令，比如`md5`，可以直接使用-help来查看选项（实际上是瞎输入一个不存在的option来被动弹出提示）。然而，因为`openssl`版本的原因，导致命令乱七八糟，比如`md5`指令还可以指定其他的算法类型，这就很蛋疼了。

总之就记住一条，只是用 dgst 指令来加密即可，其使用场景有三个：

#### 计算摘要
```shell
openssl dgst [算法名称] [需要计算摘要的文件]
```
其中算法可供选择的有：-md4、-md5、-ripemd160、-sha、-sha1、-sha224、-sha256、-sha512、-sha384、-wirlpool等等可以通过openssl dgst -help命令查看
生成文件hash值
```shell
// 进入到对应的文件夹中 
cd /Users/caoxk/Demo/opensslTest 

// 使用sha1算法对plain.text文件进行摘要计算，其中plain.text中的内容为123456 openssl dgst -sha1 plain.text 

>> SHA1(plain.text)= 7c4a8d09ca3762af61e59520943dc26494f8941b
```

#### 使用私钥签名

```shell
// 使用默认md5对plain.text进行哈希，然后使用private.pem私钥对哈希值进行签名后以16进制输出到test.text文件中 
openssl dgst -sign private.pem -hex -out test.text plain.text
```

#### 使用公钥验证签名
```shell
openssl dgst -verify public.pem -signature test.text plain.text
```

### 证书req
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

```
1，CA证书，也叫根证书或者中间级证书。如果是单向https认证的话，该证书是可选的。不安装CA证书的话，浏览器默认是不安全的。  
  
2，服务器证书，必选项。通过key，证书请求文件csr，再通过CA证书签名，生成服务器证书。  
  
3，客户端证书，可选项。若有客户端证书则是双向https验证。  
以上所有证书都可以自己生成。  
  
文件后缀  
linux系统是不以后缀名来判断文件类型的，但是为了我们能够更好地判断文件用途，所以添加各种后缀。以下是约定成俗的后缀。  
  
    *.key：密钥文件，一般是SSL中的私钥；  
  
    *.csr：证书请求文件，里面包含公钥和其他信息，通过签名后就可以生成证书；  
  
    *.crt, *.cert：证书文件，包含公钥，签名和其他需要认证的信息，比如主机名称（IP）等。  
  
    *.pem：里面一般包含私钥和证书的信息。
```

**生成私钥private.pem**
```shell
$ openssl genpkey -out private.pem -algorithm RSA -pkeyopt rsa_keygen_bits:1024
```

#### 生成证书请求文件csr
方式一：使用private.pem私钥生成csr文件并输出，期间会要求输入个人信息
```shell
openssl req -new -key private.pem -out request.csr
```
方式二：使用原有的RSA密钥生成证书请求文件，指定-batch选项，不询问申请者的信息。主体信息由命令行subj指定，且输出公钥
```shell
openssl req -new -key RSA.pem -passin pass:123456 -out client.pem -subj /C=AU/ST=Some-State/O=Internet -pubkey
```
方式三：自动生成1024位RSA密钥，并生成证书请求文件，指定-nodes文件，密钥文件不加密
```
openssl req -new -newkey rsa:1024 -out client.pem -keyout RSA.pem -subj /C=AU/ST=Some-State/O=Internet -nodes
```

查看验证csr文件，默认只会输出 csr 内容，`-text`输出包含 csr 内容的所有结构，`-noout`不输出 csr内容
```shell
openssl req -in request.csr -noout -text
```

提取csr文件中的公钥
```shell
openssl req -in request.csr -pubkey
```

生成自签名证书
```shell
// 使用private.pem 私钥对request.csr的证书请求文件进行签名并输出 
openssl req -x509 -in request.csr -out client.cer -key private.pem
```


#### 自签名证书x.509
OpenSSL实现了对证书的X.509标准编解码、PKCS#12格式的编解码以及PKCS#7的编解码功能。并提供了一种文本数据库，支持证书的管理功能，包括证书密钥产生、请求产生、证书签发、吊销和验证等功能。

事实上，OpenSSL提供的CA应用程序就是一个小型的证书管理中心（CA），实现了证书签发的整个流程和证书管理的大部分机制。

该指令功能丰富，可以查看证书信息、作为一个伪 CA 机构给证书签名（和req -x509指令一样）、证书格式转换等。因为功能是在太多，这里只介绍最主要和常用的功能：


查看证书文件信息
```shell
// 查看证书格式为DER的Apple.cer文件中的信息，默认证书为PEM格式 
openssl x509 -in Apple.cer -text -inform DER
```

查看证书中的公钥
```shell
// 只打印证书中的公钥，不打印证书 
openssl x509 -in ios_development.cer -inform DER -pubkey -noout
```

#### 证书请求
```
openssl x509 -x509toreq -in cert.pem -out req.pem -key key.pem
```

其他。
https://fatfatson.github.io/2018/07/27/openssl走一轮CA证书签发的过程和各个文件作用/


#### 证书转换
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

### 生成质数prime
```shell
$ openssl prime -generate -bits 2048 -hex
D668FDB1968891AE5D858E641B79C4BA18ABEF8C571CBE004EA5673FB3089961E4670681B794063592124D13FF553BBD5CCC81106A9E5F7D87370DD5DA6342B1DAC13CD2E584759CDEC3E76AEFB799848E48EA9C218F53FE3103E1081B8154AD41DDCB931175853FE3D433CECD886B4D94C211EAE01AE5EA93F8FBD6812A9DEF0308378EE963B3C39F80865BA0E1D957683F4ED77ADA9812091AA42E9A56F43C37185223FF9E3DD03C312E71DED072E5686873B3CA6F5F575C569FB0A10CFEA17D7FEB898A8A02549FF6E4B7A1FBCE78656D3DCF227318EEEF8E601C23AA32DF41A61F04D39FC752F70A809D636238340B7B929F0CDBA629F7DE6AAAC44D2BA5
```



