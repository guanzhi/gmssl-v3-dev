# GmSSL 3.0 Dev

  注意：本项目已经合并至  GmSSL [develop](https://github.com/guanzhi/GmSSL/tree/develop)分支，后续将在GmSSL [develop](https://github.com/guanzhi/GmSSL/tree/develop)分支进行维护，同时本项目将停止更新。 



GmSSL的2.x版本的开发始于2016年，目前主分支在功能上实现了对主要国密算法、标准和协议的覆盖，并成功应用于多种互联网场景中。但是随着GmSSL在物联网、区块链等新场景中的应用，及在密码产品合规检测过程中的实践，我们发现应用对GmSSL提出了一些新的需求。由于很难在基于OpenSSL的GmSSL 2.x版本上满足新需求，因此我们重新设计了GmSSL的架构，GmSSL也迎来第三个大版本——GmSSL 3.0。

## 编译与安装

GmSSL 3.0 采用了cmake构建系统。下载源代码后将其解压缩，进入源码目录，执行：

```bash
mkdir build
cd build
cmake ..
make
make test
sudo make install
```

## 主要新特性

* 超轻量：GmSSL 3.0大幅度降低了内存需求和二进制代码体积，不依赖动态内存，可以用于无操作系统的低功耗嵌入式环境(MCU、SOC等)，开发者也可以更容易地将国密算法和SSL协议嵌入到现有的项目中。
* 更合规：GmSSL 3.0 可以配置为仅包含国密算法和国密协议(TLCP协议)，依赖GmSSL 的密码应用更容易满足密码产品型号检测的要求，避免由于混杂非国密算法、不安全算法等导致的安全问题和合规问题。
* 更安全：TLS 1.3在安全性和通信延迟上相对之前的TLS协议有巨大的提升，GmSSL 3.0支持TLS 1.3协议和RFC 8998的国密套件。GmSSL 3.0默认支持密钥的加密保护，提升了密码算法的抗侧信道攻击能力。
* 跨平台：GmSSL 3.0更容易跨平台，构建系统不再依赖Perl，默认的CMake构建系统可以容易地和Visual Studio、Android NDK等默认编译工具配合使用，开发者也可以手工编写Makefile在特殊环境中编译、剪裁。

## 主要功能

### 密码算法

* 分组密码：SM4 (CBC, CTR, GCM), AES (GCM)
* 序列密码：ZUC/ZUC-256, ChaCha20, RC4
* 哈希函数: SM3, SHA-224/256/384/512, SHA-1, MD5
* 公钥密码算法：SM2, SM9, ECDH, ECDSA
* 椭圆曲线参数：SM2, NIST-P256
* 伪随机数生成器：HASH_DRBG (NIST.SP.800-90A)
* MAC算法：HMAC, GHASH
* 密钥导出函数：PBKDF2、HKDF

### PKI相关标准

* 数字证书：X.509证书, CRL, CSR (PKCS #10)
* 私钥加密格式：口令加密私钥PEM格式 (PKCS #8)
* 数字信封：SM2加密签名消 (GM/T 0010-2012)

### SSL协议

* TLCP 1.1，支持密码套件：`ECDHE_SM4_CBC_SM3 {0xE0,0x11}` (GB/T 38636-2020、GM/T 0024-2014)
* TLS 1.2，支持密码套件：`ECDHE_SM4_CBC_SM3 {0xE0,0x11}` (GB/T 38636-2020、GM/T 0024-2014、RFC 5246)
* TLS 1.3，支持密码套件：`TLS_SM4_GCM_SM3 {0x00,0xC6}` +ECDHE/SM2 (RFC 8998), `TLS_AES_128_GCM_SHA256` + ECDHE/ECDSA/NIST-P256

