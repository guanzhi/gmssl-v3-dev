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
 * @param conn          [in,out] 连接对象
 * @param randFnc       [in] 随机源
 * @param record        [in] 收到的记录层数据
 * @param recordlen     [in] 记录层数据
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_server_hello(TLCP_SOCKET_CONNECT *conn, TLCP_SOCKET_RandBytes_FuncPtr randFnc,
                                   uint8_t *record, size_t *recordlen);

/**
 * 写入服务端证书消息
 *
 * @param ctx                       [in] 上下文
 * @param conn                      [in,out] 连接对象
 * @param record                    [in] 收到的记录层数据
 * @param recordlen                 [in] 记录层数据
 * @param server_enc_cert           [out] 加密证书DER
 * @param server_enc_certlen        [out] 加密证书DER长度
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_server_certificate(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                         uint8_t *record, size_t *recordlen,
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
 * @param record                [in] 收到的记录层数据
 * @param recordlen             [in] 记录层数据
 * @param server_enc_cert       [in] 加密证书DER
 * @param server_enc_certlen    [in] 加密证书DER长度
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_server_key_exchange(TLCP_SOCKET_CONNECT *conn, TLCP_SOCKET_KEY *sig_key,
                                          uint8_t *record, size_t *recordlen,
                                          uint8_t *server_enc_cert, size_t server_enc_certlen);

/**
 * 写入服务端DONE消息
 *
 * @param conn              [in] 连接上下文
 * @param record            [in] 收到的记录层数据
 * @param recordlen         [in] 记录层数据
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_write_server_hello_done(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen);

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
 * @param sm3_ctx   [in] 消息Hash上下文
 * @return 1 - 成功；-1 - 失败
 */
int tlcp_socket_read_client_spec_finished(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen);

#endif //GMSSL_TLCP_SOCKET_MSG_H
