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



#ifndef GMSSL_TLCP_SOCKET_MSG_H
#define GMSSL_TLCP_SOCKET_MSG_H
#ifdef __cplusplus
extern "C" {
#endif

#include <gmssl/tlcp_socket.h>


/**
 * 读取并处理客户端Hello消息
 *
 * @param conn          [in,out]连接对象
 * @param record        [in] 收到的记录层数据
 * @param recordlen     [in] 记录层数据
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_client_hello(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen);

/**
 * 写入服务端Hello消息
 *
 * @param ctx           [in] 上下文
 * @param conn          [in,out] 连接对象
 * @param out           [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen        [in,out] 缓冲区长度，写入后增加写入长度。
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_server_hello(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                   uint8_t **out, size_t *outlen);

/**
 * 写入服务端证书消息
 *
 * @param ctx                       [in] 上下文
 * @param conn                      [in,out] 连接对象
 * @param out                       [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen                    [in,out] 缓冲区长度，写入后增加写入长度。
 * @param server_enc_cert           [out] 加密证书DER
 * @param server_enc_certlen        [out] 加密证书DER长度
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_server_certificate(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                         uint8_t **out, size_t *outlen,
                                         uint8_t *server_enc_cert, size_t *server_enc_certlen);

/**
 * 生成TLCP随机数（含有UNIX时间戳）
 *
 * @param randFnc   [in] 随机源
 * @param random    [out] 随机数
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_random_generate(TLCP_SOCKET_RandBytes_FuncPtr randFnc, uint8_t random[32]);


/**
 * 写入服务端密钥交换消息
 * @param conn                  [in] 连接上下文
 * @param sig_key               [in] 签名密钥对
 * @param out                   [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen                [in,out] 缓冲区长度，写入后增加写入长度。
 * @param server_enc_cert       [in] 加密证书DER
 * @param server_enc_certlen    [in] 加密证书DER长度
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_server_key_exchange(TLCP_SOCKET_CONNECT *conn, TLCP_SOCKET_KEY *sig_key,
                                          uint8_t **out, size_t *outlen,
                                          uint8_t *server_enc_cert, size_t server_enc_certlen);

/**
 * 写入服务端DONE消息
 *
 * @param conn              [in] 连接上下文
 * @param out               [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen            [in,out] 缓冲区长度，写入后增加写入长度。
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_server_hello_done(TLCP_SOCKET_CONNECT *conn, uint8_t **out, size_t *outlen);

/**
 * 读取客户端密钥交换消息
 *
 * 解密预主密钥，生成主密钥，派生工作密钥
 *
 * @param conn                  [in] 连接上下文
 * @param enc_key               [in] 加密密钥对
 * @param record                [in] 收到的记录层数据
 * @param recordlen             [in] 记录层数据
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_client_key_exchange(TLCP_SOCKET_CONNECT *conn, TLCP_SOCKET_KEY *enc_key,
                                         uint8_t *record, size_t *recordlen);

/**
 * 读取客户端密钥变更消息和解密验证Finished消息
 *
 * @param conn      [in] 连接上下文
 * @param record    [in] 收到的记录层数据
 * @param recordlen [in] 记录层数据
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_client_spec_finished(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen);

/**
 * 写入服务端密钥变更消息和Finished消息
 *
 * @param conn      [in] 连接上下文
 * @param out       [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen    [in,out] 缓冲区长度，写入后增加写入长度。
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_server_spec_finished(TLCP_SOCKET_CONNECT *conn, uint8_t **out, size_t *outlen);


/**
 * 接收并解密记录层消息，数据将会被解密读取到缓冲区
 *
 * @param conn    [in]      连接对象
 * @param data    [in,out]  解密消息缓冲区
 * @param datalen [in,out]  解密数据长度
 * @return  1 - 成功；-1 - 失败
 */
int tlcp_socket_read_app_data(TLCP_SOCKET_CONNECT *conn);

/**
 * 写入并加密记录层消息
 *
 * @param conn      [in]  连接对象
 * @param data      [in]  待写入数据
 * @param datalen   [in]  数据长度，长度应小于 TLCP_SOCKET_DEFAULT_FRAME_SIZE
 * @return  1 - 成功；-1 - 失败
 */
int tlcp_socket_write_app_data(TLCP_SOCKET_CONNECT *conn, const uint8_t *data, size_t datalen);


/**
 * 发送TLCP alert消息
 *
 * 如果消息为错误消息，那么将会关闭连接
 *
 * @param conn              [in] 连接上下文
 * @param alert_description [in] 错误报警描述
 */
void tlcp_socket_alert(TLCP_SOCKET_CONNECT *conn, int alert_description);

/**
 * 生成并写入客户端Hello消息
 *
 * @param ctx       [in] 上下文
 * @param conn      [in] socket连接
 * @param record    [in,out] 收到的记录层数据
 * @param recordlen [in,out] 记录层数据
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_client_hello(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                   uint8_t *record, size_t *recordlen);

/**
 * 读取并处理服务端Hello消息
 *
 * @param conn      [in] socket连接
 * @param record    [in,out] 收到的记录层数据
 * @param recordlen [in,out] 记录层数据
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_server_hello(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen);


/**
 * 读取并解析服务端证书
 *
 * @param ctx                   [in] 上下文
 * @param conn                  [in] socket连接
 * @param record                [in,out] 收到的记录层数据
 * @param recordlen             [in,out] 记录层数据
 * @param server_certs          [in,out] 服务端证书（按顺序签名证书、加密证书）
 * @param enc_cert_vector       [out] 加密证书DER编码向量
 * @param enc_cert_vector_len   [out] 加密证书DER编码向量长度
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_server_certs(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                  uint8_t *record, size_t *recordlen,
                                  X509_CERTIFICATE server_certs[2],
                                  uint8_t *enc_cert_vector, size_t *enc_cert_der_len);

/**
 * 读取并处理服务端密钥交换
 *
 * 验证签名值
 *
 * @param conn                  [in] socket连接
 * @param record                [in,out] 收到的记录层数据
 * @param recordlen             [in,out] 记录层数据
 * @param server_sig_cert       [in] 服务端签名证书
 * @param enc_cert_vector       [in] 服务端加密证书向量
 * @param enc_cert_vector_len   [in] 服务端加密证书向量长度
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_server_key_exchange(TLCP_SOCKET_CONNECT *conn,
                                         uint8_t *record, size_t *recordlen,
                                         X509_CERTIFICATE *server_sig_cert,
                                         uint8_t *enc_cert_vector, size_t enc_cert_vector_len);

/**
 * 读取并处理证书请求(如果存在)和服务端Done消息
 *
 * @param ctx                   [in] 上下文
 * @param conn                  [in] socket连接
 * @param record                [in,out] 记录层数据
 * @param recordlen             [in,out] 记录层数据长度
 * @param need_auth             [out] 是否需要客户端认证
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_cert_req_server_done(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn, uint8_t *record,
                                          size_t *recordlen, uint8_t *need_auth);

/**
 * 生成预主密钥工作密钥，并写入客户端密钥交换消息
 *
 * @param ctx                   [in] 上下文
 * @param conn                  [in] socket连接
 * @param out                   [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen                [in,out] 缓冲区长度，写入后增加写入长度。
 * @param server_enc_cert       [in] 加密证书
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_client_key_exchange(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                          uint8_t **out, size_t *outlen,
                                          X509_CERTIFICATE *server_enc_cert);

/**
 * 写入密钥变更消息并生成finished消息
 *
 * @param conn                  [in] socket连接
 * @param out                   [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen                [in,out] 缓冲区长度，写入后增加写入长度。
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_client_spec_finished(TLCP_SOCKET_CONNECT *conn, uint8_t **out, size_t *outlen);

/**
 * 读取服务端密钥变更消息，并验证服务端finished消息
 *
 * @param conn                  [in] socket连接
 * @param record                [in,out] 记录层数据
 * @param recordlen             [in,out] 记录层数据长度
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_server_spec_finished(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen);

/**
 * 写入客户端认证证书
 *
 * @param ctx                   [in] 上下文
 * @param conn                  [in] socket连接
 * @param out               [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen            [in,out] 缓冲区长度，写入后增加写入长度。
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_client_certificate(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                         uint8_t **out, size_t *outlen);

/**
 * 生成客户端证书验证消息并发送
 *
 * @param ctx                   [in] 上下文
 * @param conn                  [in] socket连接
 * @param out                   [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen                [in,out] 缓冲区长度，写入后增加写入长度。
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_client_cert_verify(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                         uint8_t **out, size_t *outlen);

/**
 * 生成并写入证书请求消息
 *
 * @param ctx                   [in] 上下文
 * @param conn                  [in] socket连接
 * @param out                   [in,out] 缓冲区，写入后会产生偏移。
 * @param outlen                [in,out] 缓冲区长度，写入后增加写入长度。
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_cert_req(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                               uint8_t **out, size_t *outlen);

/**
 * 读取客户端证书消息
 *
 * @param conn                 [in] socket连接
 * @param record               [in,out] 记录层数据
 * @param recordlen            [in,out] 记录层数据长度
 * @param client_cert          [out] 客户端证书
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_client_cert(TLCP_SOCKET_CONNECT *conn,
                                 uint8_t *record, size_t *recordlen,
                                 X509_CERTIFICATE *client_cert);

/**
 * 读取并验证客户端验证消息
 *
 * @param conn                 [in] socket连接
 * @param record               [in,out] 记录层数据
 * @param recordlen            [in,out] 记录层数据长度
 * @param client_cert          [in] 客户端证书
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_client_cert_verify(TLCP_SOCKET_CONNECT *conn,
                                        uint8_t *record, size_t *recordlen,
                                        X509_CERTIFICATE *client_cert);

/**
 * 发送粘黏在一起的记录层数据
 *
 * @param conn [in] 连接对象
 * @param buff [in] 缓冲区
 * @param records_len [in] 多个记录层数据包的总长度
 * @return  1 - 成功；-1 - 失败
 */
int tlcp_socket_send_records(TLCP_SOCKET_CONNECT *conn, const uint8_t *buff, size_t records_len);

#ifdef  __cplusplus
}
#endif
#endif //GMSSL_TLCP_SOCKET_MSG_H
