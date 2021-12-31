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
typedef int (*TLCP_SOCKET_RandBytes_FuncPtr)(uint8_t *buf, size_t len);

/**
 * TLCP签名接口，用于实现签名
 *
 * @param ctx     [in] socket密钥上下文，该参数在每次调用该方法时传入，请根据情况在函数内部强制类型转换使用。
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
 * @param ctx             [in] socket密钥上下文，该参数在每次调用该方法时传入，请根据情况在函数内部强制类型转换使用。
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
typedef struct {
    void                          *ctx;      // 上下文，可以是一个设备句柄或会话指针用于函数调用。
    X509_CERTIFICATE              *cert;     // 证书（公钥）
    TLCP_SOCKET_Signer_FuncPtr    signer;    // 密钥对的签名实现
    TLCP_SOCKET_Decrypter_FuncPtr decrypter; // 密钥对的解密实现
}           TLCP_SOCKET_KEY;

typedef struct {
    TLCP_SOCKET_RandBytes_FuncPtr rand;               // 随机源
    X509_CERTIFICATE              *root_certs;        // 根证书列表，客户端用于验证服务端证书，服务端用于验证客户端证书，如果为空表示不验证。
    size_t                        root_cert_len;      // 根证书数量
    TLCP_SOCKET_KEY               *server_sig_key;    // 服务器签名密钥对
    TLCP_SOCKET_KEY               *server_enc_key;    // 服务器加密密钥对
    TLCP_SOCKET_KEY               *client_sig_key;    // 客户端认证密钥对
    // ##################### 私有 #####################
    int                           _sock;              // SocketFD
}           TLCP_SOCKET_CTX;


#define TLCP_SOCKET_SERVER_END 0
#define TLCP_SOCKET_CLIENT_END 1

/**
 * TLCP SOCKET连接
 *
 * 用于维护在连接过程中需要上下文数据
 *
 * 注：握手阶段数据由Accept内部维护，握手结束后初始化完成连接参数。
 */
typedef struct {
    uint8_t record_r[TLS_MAX_RECORD_SIZE]; // 数据读取缓冲区
    uint8_t record_w[TLS_MAX_RECORD_SIZE]; // 数据写入缓冲区

    int     sock;               // Socket FD
    int     version;            // 协议版本
    int     cipher_suite;       // 密码套件
    size_t  session_id_len;     // 会话ID长度
    uint8_t entity;             // 0 - server, 1 - client
    uint8_t session_id[32];     // 会话ID

    uint8_t client_random[32];  // 客户端随机数
    uint8_t server_random[32];  // 服务端随机数

    uint8_t client_seq_num[8];  // 客户端消息序列号
    uint8_t server_seq_num[8];  // 服务端消息序列号

    uint8_t hash_size;                  // HASH分组长度
    uint8_t key_material_length;        // 对称密钥长度
    uint8_t fixed_iv_length;            // IV长度

    uint8_t master_secret[48];          // 主密钥
    uint8_t key_block[96];              // 工作密钥，下面是各密钥的指针

    uint8_t *client_write_MAC_secret;   // 客户端写MAC密钥
    uint8_t *server_write_MAC_secret;   // 服务端写MAC密钥
    uint8_t *client_write_key;          // 客户端写加密密钥
    uint8_t *server_write_key;          // 服务端写加密密钥
    uint8_t *client_write_IV;           // 客户端写IV
    uint8_t *server_write_IV;           // 服务端写IV

} TLCP_SOCKET_CONNECT;

/**
 * 创建 TLCP listener接收TLCP连接
 *
 * @param ctx  [in,out] TLCP上下文
 * @param port [in]     服务监听端口
 * @return 1 - 读取成功；-1 - 读取失败
 */
int TLCP_SOCKET_Listen(TLCP_SOCKET_CTX *ctx, int port);

/**
 * 通过文件描述符创建 TLCP listener接收TLCP连接
 *
 * @param ctx [in,out] TLCP上下文
 * @param fd  [in]     文件描述符，如socket fd
 * @return 1 - 读取成功；-1 - 读取失败
 */
int TLCP_SOCKET_Listen_raw(TLCP_SOCKET_CTX *ctx, int fd);

/**
 * 关闭TLCP服务端监听
 *
 * @param ctx [in] 上下文
 */
void TLCP_SOCKET_Close(TLCP_SOCKET_CTX *ctx);

/**
 * 服务端接受TLCP连接 并进行握手
 *
 * 该方法将会发生阻塞，直到发现连接或服务关闭
 *
 * @param ctx [in] 上下文
 * @param conn [out] 连接对象
 * @return 1 - 连接成功; -1 - 连接失败
 */
int TLCP_SOCKET_Accept(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn);

/**
 * 从TLCP连接中解密校验读取数据
 *
 * @param conn [in] TCLP连接
 * @param buf  [out] 读取数据缓冲区
 * @param len  [out] 读取数据长度
 * @return 1 - 读取成功；-1 - 读取失败
 */
int TLCP_SOCKET_Read(TLCP_SOCKET_CONNECT *conn, uint8_t *buf, size_t *len);

/**
 * 向TLCP连接中加密验证写入数据
 *
 * @param conn [in] TCLP连接
 * @param data  [in] 读取数据缓冲区
 * @param datalen  [in] 读取数据长度
 * @return 1 - 写入成功；-1 - 写入失败
 */
int TLCP_SOCKET_Write(TLCP_SOCKET_CONNECT *conn, uint8_t *data, size_t datalen);

/**
 * 连接TLCP服务端
 *
 * @param ctx  [in] 上下文
 * @param conn [out] TLCP连接
 * @return 1 - 连接成功；-1 - 连接失败
 */
int TLCP_SOCKET_Connect(TLCP_SOCKET_CONNECT *ctx, TLS_CONNECT *conn);

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
 * @param sm2_key       [in] SM2私钥指针
 * @return 1 - 连接成功；-1 - 连接失败
 */
int TLCP_SOCKET_gmssl_key(TLCP_SOCKET_KEY *socket_key, X509_CERTIFICATE *cert, SM2_KEY *sm2_key);

#endif //GMSSL_TLCP_SOCKET_H
