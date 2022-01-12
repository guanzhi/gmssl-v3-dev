/*
 * Copyright (c) 2021 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */



#ifndef GMSSL_TLCP_SOCKET_H
#define GMSSL_TLCP_SOCKET_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <gmssl/tls.h>
#include <gmssl/x509.h>

/**
 * 在TLCP通信过程最主要的是要确保签名和解密的密钥的安全性
 * 通信过程中的HMAC、对称加解密，可以委托GMSSL软件实现
 * 因此抽象 与密钥计算相关的计算部分为接口，用于适配不同密码介质需要。
 *
 * 在密码领域中随机数的质量决定了安全性，因此将随机发生器进行抽象封装成接口
 * 由外部提供随机源。
 *
 * 接口定义，小写字母开头函数表示内部使用，大写字母开头表示对外暴露，私有接口使用static修饰
 * 如：tlcp_*        表示内部使用
 * 如：TLCP_SOCKET_* 表示对外暴露接口
 */


/**
 * 获取随机字节（随机源）
 *
 * 注：随机数一般来说不需要上下文
 *
 * @param buf [out] 缓冲区
 * @param len [in] 缓冲区长度
 * @return 1 - 读取成功；-1 - 读取失败
 */
typedef rand_src TLCP_SOCKET_RandBytes_FuncPtr;

/**
 * TLCP签名接口，用于实现签名
 *
 * @param ctx     [in] TLCP_SOCKET_KEY.ctx，该参数在每次调用该方法时传入，请根据情况在函数内部强制类型转换使用。
 * @param msg     [in] 待签名原文
 * @param msglen  [in] 待签名原文长度
 * @param sig     [out] 签名值
 * @param siglen  [out] 签名值长度
 * @return 1 - 成功；-1 - 失败
 */
typedef int (*TLCP_SOCKET_Signer_FuncPtr)(void *ctx, uint8_t *msg, size_t msglen, uint8_t *sig, size_t *siglen);

/**
 * TLCP解密接口，用于数据解密
 *
 * @param ctx             [in] TLCP_SOCKET_KEY.ctx，该参数在每次调用该方法时传入，请根据情况在函数内部强制类型转换使用。
 * @param ciphertext      [in] 密文
 * @param ciphertext_len  [in] 密文长度
 * @param plaintext       [out] 明文
 * @param plaintext_len   [out] 明文长度
 * @return 1 - 成功；-1 - 失败
 */
typedef int (*TLCP_SOCKET_Decrypter_FuncPtr)(void *ctx, uint8_t *ciphertext, size_t ciphertext_len,
                                             uint8_t *plaintext, size_t *plaintext_len);

/**
 * TLCP Socket 密钥对接口
 *
 * 公钥、证书、签名、解密
 */
typedef struct TLCP_SOCKET_KEY_st {
    void                          *ctx;      // 上下文，可以是一个设备句柄或会话指针用于函数调用。
    X509_CERTIFICATE              *cert;     // 证书（公钥）
    TLCP_SOCKET_Signer_FuncPtr    signer;    // 密钥对的签名实现
    TLCP_SOCKET_Decrypter_FuncPtr decrypter; // 密钥对的解密实现

} TLCP_SOCKET_KEY;


struct TLCP_SOCKET_CONNECT_st;
typedef struct TLCP_SOCKET_CONNECT_st TLCP_SOCKET_CONNECT;

/**
 * 报警协议处理器
 *
 * 每当连接收到或发送报警协议时将触发该函数
 * @param conn              [in] 连接上下文
 * @param alert_description [in] 报警描述信息
 */
typedef void (*TLCP_SOCKET_Alert_Handler_FuncPtr)(TLCP_SOCKET_CONNECT *conn, uint8_t alert_description);

/**
 * SOCKET配置上下文
 */
typedef struct TLCP_SOCKET_CONFIG_st {
    TLCP_SOCKET_RandBytes_FuncPtr     rand;             // 随机源
    X509_CERTIFICATE                  *root_certs;      // 根证书列表，客户端用于验证服务端证书，服务端用于验证客户端证书，如果为空表示不验证。
    int                               root_cert_len;    // 根证书数量
    TLCP_SOCKET_KEY                   *server_sig_key;  // 服务器签名密钥对
    TLCP_SOCKET_KEY                   *server_enc_key;  // 服务器加密密钥对
    TLCP_SOCKET_KEY                   *client_sig_key;  // 客户端认证密钥对
    TLCP_SOCKET_Alert_Handler_FuncPtr alert_handler;    // 报警消息处理器

} TLCP_SOCKET_CONFIG;

#define TLCP_SOCKET_SERVER_END 0
#define TLCP_SOCKET_CLIENT_END 1
#define TLCP_SOCKET_DEFAULT_FRAME_SIZE 4096

#define TLCP_SOCKET_CONNECTED 0     // 成功建立TLCP Socket连接
#define TLCP_SOCKET_UNCONNECTED 1   // 未建立TLCP Socket连接

/**
 * TLCP SOCKET连接
 *
 * 用于维护在连接过程中需要上下文数据
 *
 * 注：握手阶段数据由Accept内部维护，握手结束后初始化完成连接参数。
 * 其中以"_"开头的参数表示私有参数，不应该在外部访问。
 */
struct TLCP_SOCKET_CONNECT_st {
    TLCP_SOCKET_CONFIG *config;            // 连接配置上下文
    int                sock;               // Socket FD
    int                version;            // 协议版本
    int                cipher_suite;       // 密码套件
    size_t             session_id_len;     // 会话ID长度
    uint8_t            session_id[32];     // 会话ID

    uint8_t entity;                     // 0 - server, 1 - client
    uint8_t connected;                  // 0 - 未连接; 1 - 已经建立连接
    uint8_t hash_size;                  // HASH分组长度
    uint8_t key_material_length;        // 对称密钥长度
    uint8_t fixed_iv_length;            // IV长度

    uint8_t _client_random[32];  // 客户端随机数
    uint8_t _server_random[32];  // 服务端随机数

    uint8_t _client_seq_num[8];  // 客户端消息序列号
    uint8_t _server_seq_num[8];  // 服务端消息序列号

    // 密钥
    uint8_t      _master_secret[48];         // 主密钥
    uint8_t      _key_block[96];             // 工作密钥，下面是各密钥的指针
    SM3_HMAC_CTX _client_write_mac_ctx;      // 客户端写MAC密钥
    SM3_HMAC_CTX _server_write_mac_ctx;      // 服务端写MAC密钥
    SM4_KEY      _client_write_enc_key;      // 客户端写加密密钥
    SM4_KEY      _server_write_enc_key;      // 服务端写加密密钥
    uint8_t      *_client_write_IV;          // 客户端写IV
    uint8_t      *_server_write_IV;          // 服务端写IV

    // 连接上下文参数
    uint8_t record[TLS_RECORD_MAX_PLAINDATA_SIZE];      // 解密后记录层消息
    uint8_t _raw_input[TLS_MAX_RECORD_SIZE];            // 未解密原始数据
    uint8_t *_p;                                        // 记录层中数据游标指针，随着读取逐渐向后移动
    size_t  _buf_remain;                                // 记录层中数据剩余长度

    SM3_CTX *_sm3_ctx;                                  // 用于握手阶段的校验码计算，握手结束后置为NULL
};

/**
 * 连接监听器，负责接收和建立连接
 */
typedef struct {
    TLCP_SOCKET_CONFIG *config;          // 配置上下文
    int                _sock;            // Server SocketFD
} TLCP_SOCKET_Listener;

/**
 * 创建 TLCP listener接收TLCP连接
 *
 * @param config    [in,out] 配置信息
 * @param ln        [out] 连接监听器
 * @param port      [in]     服务监听端口
 * @return 1 - 读取成功；-1 - 读取失败
 */
int TLCP_SOCKET_Listen(TLCP_SOCKET_CONFIG *config, TLCP_SOCKET_Listener *ln, int port);

/**
 * 通过文件描述符创建 TLCP listener接收TLCP连接
 *
 * @param config    [in,out] 配置信息
 * @param ln        [out] 连接监听器
 * @param fd        [in]     文件描述符，如socket fd
 * @return 1 - 读取成功；-1 - 读取失败
 */
int TLCP_SOCKET_Listen_raw(TLCP_SOCKET_CONFIG *config, TLCP_SOCKET_Listener *ln, int fd);

/**
 * 关闭TLCP服务端监听
 *
 * @param ln [in] 监听器
 */
void TLCP_SOCKET_Close(TLCP_SOCKET_Listener *ln);

/**
 * 服务端接受TLCP连接 并进行握手
 *
 * 该方法将会发生阻塞，直到发现连接或服务关闭
 *
 * @param ln   [in] 监听器
 * @param conn [out] 连接对象
 * @return 1 - 连接成功; -1 - 连接失败
 */
int TLCP_SOCKET_Accept(TLCP_SOCKET_Listener *ln, TLCP_SOCKET_CONNECT *conn);

/**
 * 从TLCP连接中解密校验读取数据
 *
 * 设计参考: unistd.h write()
 *
 * @param conn      [in] TCLP连接
 * @param buf       [out] 读取数据缓冲区
 * @param count     [in] 缓冲区长度
 * @return 成功时返回读取字节数；失败时返回-1，并存储错误代码errno
 */
ssize_t TLCP_SOCKET_Read(TLCP_SOCKET_CONNECT *conn, void *buf, size_t count);

/**
 * 向TLCP连接中加密验证写入数据
 *
 * 设计参考: unistd.h read
 *
 * @param conn      [in] TCLP连接
 * @param buf       [in] 待写入数据
 * @param count     [in] 待写入数据数量（字节）
 * @return 成功时返回写入字节数；失败时返回-1，并存储错误代码errno
 */
ssize_t TLCP_SOCKET_Write(TLCP_SOCKET_CONNECT *conn, void *buf, size_t count);

/**
 * 连接TLCP服务端，并进行TLCP握手
 *
 * @param config        [in] 配置信息
 * @param conn          [out] TLCP连接
 * @param hostname      [in] 主机地址（IP）
 * @param port          [in] 主机端口
 * @return 1 - 连接成功；-1 - 连接失败
 */
int TLCP_SOCKET_Dial(TLCP_SOCKET_CONFIG *config, TLCP_SOCKET_CONNECT *conn, const char *hostname, int port);

/**
 * 断开TLCP连接
 *
 * @param conn [in] 连接
 */
void TLCP_SOCKET_Connect_Close(TLCP_SOCKET_CONNECT *conn);

/**
 * 创建国密SSL类型的 SOCKET密钥对
 *
 * @param socket_key    [in,out] 密钥对指针
 * @param cert          [in] 证书指针
 * @param sm2_key       [in] SM2私钥
 * @return 1 - 成功；-1 - 失败
 */
int TLCP_SOCKET_GMSSL_Key(TLCP_SOCKET_KEY *socket_key, X509_CERTIFICATE *cert, SM2_KEY *sm2_key);

#ifdef  __cplusplus
}
#endif
#endif //GMSSL_TLCP_SOCKET_H
