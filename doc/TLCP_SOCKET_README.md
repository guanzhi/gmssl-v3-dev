# TLCP SOCKET使用说明

支持密码套件：

- `ECDHE_SM4_CBC_SM3 {0xE0,0x11}` (GB/T 38636-2020、GM/T 0024-2014)

测试用例：

- [tlcpsockettest](../tests/tlcpsockettest.c)
  - TLCP服务端测试：`server_test()`
  - TLCP客户端 单向身份认证测试：`client_conn_test()`
  - TLCP客户端 双向身份认证测试：`client_auth_test()`

## TLCP SOCKET API

### 创建TLCP监听器

原型：

```c
int TLCP_SOCKET_Listen(TLCP_SOCKET_CONFIG *config,
                       TLCP_SOCKET_Listener *ln, int port);
```

描述： 创建 TLCP listener接收TLCP连接

参数：

- `config` [in,out] 配置信息
- `ln`     [out] 连接监听器
- `port`   [in] 服务监听端口

返回值：

- `1`  成功
- `-1` 失败

### 创建TLCP监听器（文件描述符）

原型：

```c
int TLCP_SOCKET_Listen_raw(TLCP_SOCKET_CONFIG *config, 
                           TLCP_SOCKET_Listener *ln, int fd);
```

描述： 通过文件描述符创建 TLCP listener接收TLCP连接

参数：

- `config` [in,out] 配置信息
- `ln` [out] 连接监听器
- `fd` [in] 文件描述符，如socket fd

返回值：

- `1`  成功
- `-1` 失败

### 关闭TLCP服务端监听

原型：

```c
void TLCP_SOCKET_Close(TLCP_SOCKET_Listener *ln);
```

描述： 关闭TLCP服务端监听

参数：

- `ln` [in] 监听器

返回值：无

### 接收TLCP连接

原型：

```c
int TLCP_SOCKET_Accept(TLCP_SOCKET_Listener *ln, TLCP_SOCKET_CONNECT *conn);
```

描述： 服务端接受TLCP连接 并进行握手

参数：

- `ln` [in] 监听器
- `conn` [out] 连接对象

返回值：

- `1`  成功
- `-1` 失败

### 读取数据

原型：

```c
ssize_t TLCP_SOCKET_Read(TLCP_SOCKET_CONNECT *conn,
                         void *buf, size_t count);
```

描述：从TLCP连接中解密校验读取数据，设计参考: `unistd.h write()`

参数：

- `conn`  [in] TCLP连接
- `buf`   [out] 读取数据缓冲区
- `count` [in] 缓冲区长度

返回值：

- 成功时返回读取字节数；
- 失败时返回`-1`，并存储错误代码errno

### 写入数据

原型：

```c
ssize_t TLCP_SOCKET_Write(TLCP_SOCKET_CONNECT *conn, void *buf, size_t count);
```

描述： 向TLCP连接中加密验证写入数据，设计参考: `unistd.h read`

参数：

- `conn`  [in] TCLP连接
- `buf`   [in] 待写入数据
- `count` [in] 待写入数据数量（字节）

返回值：

- 成功时返回写入字节数
- 失败时返回`-1`，并存储错误代码errno

### TLCP拨号

原型：

```c
int TLCP_SOCKET_Dial(TLCP_SOCKET_CONFIG *config, TLCP_SOCKET_CONNECT *config, 
                     const char *hostname, int port);
```

描述：连接TLCP服务端，并进行TLCP握手

参数：

- `config`   [in] 配置信息
- `conn`     [out] TLCP连接
- `hostname` [in] 主机地址（IP）
- `port`     [in] 主机端口

返回值：

- `1`  成功
- `-1` 失败

### 关闭TLCP连接

原型：

```c
void TLCP_SOCKET_Connect_Close(TLCP_SOCKET_CONNECT *conn);
```

描述： 断开TLCP连接

参数：

- `conn` [in] 连接

返回值： 无

### 创建SOCKET密钥对

原型： 

```c
int TLCP_SOCKET_GMSSL_Key(TLCP_SOCKET_KEY *socket_key, X509_CERTIFICATE *cert, SM2_KEY *sm2_key);
```

描述：创建GMSSL类型的 SOCKET密钥对，包含SM2密钥对和关键证书。

参数：

- `socket_key` [in,out] 密钥对指针
- `cert`       [in] 证书指针
- `sm2_key`    [in] SM2私钥

返回值：

- `1`  成功
- `-1` 失败

## 接口

在TLCP通信过程最主要的是要确保签名和解密的密钥的安全性。

通信过程中的HMAC、对称加解密。
可以委托GMSSL软件实现，因此抽象 与密钥计算相关的计算部分为接口，用于适配不同密码介质需要。
在密码领域中随机数的质量决定了安全性，因此将随机发生器进行抽象封装成接口，由外部提供随机源。

### 密钥对抽象

```c
typedef struct TLCP_SOCKET_KEY_st {
    void                          *ctx;      // 上下文，可以是一个设备句柄或会话指针用于函数调用。
    X509_CERTIFICATE              *cert;     // 证书（公钥）
    TLCP_SOCKET_Signer_FuncPtr    signer;    // 密钥对的签名实现
    TLCP_SOCKET_Decrypter_FuncPtr decrypter; // 密钥对的解密实现

} TLCP_SOCKET_KEY;
```

- `ctx` 密钥上下文，可以是一个句柄用于在运算是访问。
- `cert` 密钥关联的证书。
- `signer` 签名接口
- `decrypter` 加密接口



**签名接口原型**

```c
int TLCP_SOCKET_Signer_FuncPtr(void *ctx,
                               uint8_t *msg, size_t msglen,
                               uint8_t *sig, size_t *siglen);
```

参数：

- `ctx` [in] TLCP_SOCKET_KEY.ctx，该参数在每次调用该方法时传入，请根据情况在函数内部强制类型转换使用。
- `msg` [in] 待签名原文
- `msglen` [in] 待签名原文长度
- `sig` [out] 签名值
- `siglen` [out] 签名值长度

返回值：

- `1`  成功
- `-1` 失败



**解密接口原型**

```c
int TLCP_SOCKET_Decrypter_FuncPtr(void *ctx,
                                  uint8_t *ciphertext, size_t ciphertext_len,
                                  uint8_t *plaintext, size_t *plaintext_len);
```

参数：

- `ctx`             [in] TLCP_SOCKET_KEY.ctx，该参数在每次调用该方法时传入，请根据情况在函数内部强制类型转换使用。
- `ciphertext`      [in] 密文
- `ciphertext_len`  [in] 密文长度
- `plaintext`       [out] 明文
- `plaintext_len`   [out] 明文长度

返回值：

- `1`  成功
- `-1` 失败
