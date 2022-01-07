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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <gmssl/tlcp_socket.h>
#include <gmssl/tlcp_socket_msg.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <arpa/inet.h>


int TLCP_SOCKET_Listen(TLCP_SOCKET_CTX *ctx, int port) {
    struct sockaddr_in server_addr;
    int                sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error_print();
        return -1;
    }
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(port);
    // 绑定端口，任意来源。
    if (bind(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        error_print();
        return -1;
    }
    error_print_msg("TLCP Socket listen in port %d\n", port);
    return TLCP_SOCKET_Listen_raw(ctx, sock);
}

int TLCP_SOCKET_Listen_raw(TLCP_SOCKET_CTX *ctx, int fd) {
    if (ctx == NULL) {
        error_print();
        return -1;
    }
    if (ctx->rand == NULL) {
        // 如果没有提供随机源，那么使用GMSSL默认随机源
        ctx->rand = rand_bytes;
    }
    if (ctx->server_sig_key == NULL || ctx->server_enc_key == NULL) {
        error_print();
        return -1;
    }
    // 参数检查
    ctx->_sock = fd;

    // 启动监听
    if (listen(ctx->_sock, 16) != 0) {
        error_print();
        return -1;
    }
    return 1;
}

void TLCP_SOCKET_Close(TLCP_SOCKET_CTX *ctx) {
    if (ctx != NULL && ctx->_sock != 0) {
        close(ctx->_sock);
    }
}

/**
 * 服务端接受TLCP连接 并进行握手
 *
 * 该方法将会发生阻塞，直到发现连接或服务关闭
 *
 * @param ctx  [in] 上下文
 * @param conn [out] 连接对象
 * @return 1 - 连接成功; -1 - 连接失败
 */
int TLCP_SOCKET_Accept(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn) {
    uint8_t            record[TLS_MAX_RECORD_SIZE];
    size_t             recordlen          = 0;
    uint8_t            server_enc_cert[TLS_MAX_CERTIFICATES_SIZE];
    size_t             server_enc_certlen = 0;
    uint8_t            need_client_auth   = 0;
    struct sockaddr_in client_addr;
    socklen_t          client_addrlen     = sizeof(client_addr);
    SM3_CTX            sm3_ctx; // 握手消息Hash


    if (ctx == NULL || conn == NULL) {
        error_puts("illegal parameter");
        return -1;
    }
    need_client_auth = ctx->root_cert_len > 0 && ctx->root_certs != NULL;
    memset(conn, 0, sizeof(*conn));

    // 阻塞接收连接
    if ((conn->sock = accept(ctx->_sock, (struct sockaddr *) &client_addr, &client_addrlen)) < 0) {
        error_print();
        return -1;
    }

    // 开始握手协议
    sm3_init(&sm3_ctx);
    conn->_sm3_ctx  = &sm3_ctx;
    conn->entity    = TLCP_SOCKET_SERVER_END;
    conn->connected = TLCP_SOCKET_UNCONNECTED;

    tls_trace("<<<< ClientHello\n");
    if (tlcp_socket_read_client_hello(conn, record, &recordlen) != 1) {
        return -1;
    }

    tls_trace(">>>> ServerHello\n");
    if (tlcp_socket_write_server_hello(conn, ctx->rand, record, &recordlen) != 1) {
        return -1;
    }

    tls_trace(">>>> ServerCertificate\n");
    if (tlcp_socket_write_server_certificate(ctx, conn, record, &recordlen,
                                             server_enc_cert, &server_enc_certlen) != 1) {
        return -1;
    }

    tls_trace(">>>> ServerKeyExchange\n");
    if (tlcp_socket_write_server_key_exchange(conn, ctx->server_sig_key,
                                              record, &recordlen,
                                              server_enc_cert, server_enc_certlen) != 1) {
        return -1;
    }

    if (need_client_auth) {
        // TODO: Certificate Request消息
    }

    tls_trace(">>>> ServerHelloDone\n");
    if (tlcp_socket_write_server_hello_done(conn, record, &recordlen) != 1) {
        return -1;
    }

    if (need_client_auth) {
        // TODO: Client Certificate消息
    }
    tls_trace("<<<< ClientKeyExchange\n");
    if (tlcp_socket_read_client_key_exchange(conn, ctx->server_enc_key, record, &recordlen) != 1) {
        return -1;
    }

    if (need_client_auth) {
        // TODO: Certificate Verify消息
    }
    // 读取并处理密钥变更消息和客户端finished消息
    if (tlcp_socket_read_client_spec_finished(conn, record, &recordlen) != 1) {
        return -1;
    }
    // 服务端变更密码协议，发送finished消息
    if (tlcp_socket_write_server_spec_finished(conn, record, &recordlen) != 1) {
        return -1;
    }
    conn->connected = TLCP_SOCKET_CONNECTED;
    conn->_sm3_ctx  = NULL;
    return 1;
}

ssize_t TLCP_SOCKET_Read(TLCP_SOCKET_CONNECT *conn, void *buf, size_t count) {
    size_t n = 0;
    if (conn == NULL || conn->sock <= 0) {
        return 0;
    }

    if (buf == NULL || count <= 0) {
        error_puts("illegal parameter buf");
        return 0;
    }

    if (conn->_buf_remain == 0) {
        if (tlcp_socket_read_record(conn) == -1) {
            error_print();
            return 0;
        }
        // 对读取的消息进行错误处理
        if (conn->record[0] == TLS_record_alert) {
            switch (conn->record[0]) {
                case TLS_alert_level_warning:
                    // 忽略错误继续读取
//                    return TLCP_SOCKET_Read(conn, buf, count);
                case TLS_alert_level_fatal:
                    if (conn->record[1] == TLS_alert_close_notify) {
                        return EOF;
                    } else {
                        error_print_msg("remote error alert description %d", conn->record[2]);
                        return 0;
                    }
                default:
                    error_puts("unknown alert message type");
                    return 0;
            }
        }
    }
    // 从读入的缓冲区中获取需要复制的数据数量
    if (count > conn->_buf_remain) {
        n = conn->_buf_remain;
    } else {
        n = count;
    }
    // 从缓冲区中复制数据
    memcpy(buf, conn->_p, n);
    // 缓冲区 偏移指针 和 剩余数据数量
    conn->_p += n;
    conn->_buf_remain -= n;
    return (ssize_t) n;
}

ssize_t TLCP_SOCKET_Write(TLCP_SOCKET_CONNECT *conn, void *buf, size_t count) {
    uint8_t *p     = buf;
    size_t  offset = 0;

    if (conn == NULL || buf == NULL || count == 0) {
        error_puts("illegal parameter");
        return -1;
    }
    // 分段发送
    for (;;) {
        if (offset + TLCP_SOCKET_DEFAULT_FRAME_SIZE < count) {
            if (tlcp_socket_write_record(conn, p, TLCP_SOCKET_DEFAULT_FRAME_SIZE) != 1) {
                return -1;
            }
            offset += TLCP_SOCKET_DEFAULT_FRAME_SIZE;
            p = buf + offset;
        } else {
            if (tlcp_socket_write_record(conn, p, count - offset) != 1) {
                return -1;
            }
            break;
        }
    }
    return (ssize_t) count;
}


int TLCP_SOCKET_Dial(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn, const char *hostname, int port) {
    SM3_CTX            sm3_ctx;         // 握手消息Hash
    X509_CERTIFICATE   server_certs[2]; // 服务端证书：签名证书[0]、加密证书[1]
    uint8_t            record[TLS_MAX_RECORD_SIZE]        = {0};
    uint8_t            enc_cert_vector[TLS_MAX_CERT_SIZE] = {0};   // 加密证书DER向量
    size_t             recordlen                          = 0;
    size_t             enc_cert_vector_len                = 0;     // 加密证书DER向量长度
    struct sockaddr_in server_addr                        = {0};
    uint8_t            need_auth                          = 0;     // 是否需要客户端身份认证 0 - 不需要; 1 - 需要

    if (conn == NULL || ctx == NULL || hostname == NULL || port <= 0) {
        error_puts("illegal parameter");
        return -1;
    }

    server_addr.sin_addr.s_addr = inet_addr(hostname);
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(port);
    memset(conn, 0, sizeof(*conn));

    if ((conn->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error_print();
        return -1;
    }
    if (connect(conn->sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        error_print();
        return -1;
    }

    sm3_init(&sm3_ctx);
    conn->_sm3_ctx  = &sm3_ctx;
    conn->entity    = TLCP_SOCKET_CLIENT_END;
    conn->connected = TLCP_SOCKET_UNCONNECTED;
    tls_record_set_version(record, TLS_version_tlcp);

    // 开始握手
    tls_trace(">>>> ClientHello\n");
    if (tlcp_socket_write_client_hello(ctx, conn, record, &recordlen) != 1) {
        // perror("ClientHello");
        return -1;
    }
    tls_trace("<<<< ServerHello\n");
    if (tlcp_socket_read_server_hello(conn, record, &recordlen) != 1) {
        return -1;
    }
    tls_trace("<<<< ServerCertificate\n");
    if (tlcp_socket_read_server_certs(ctx, conn,
                                      record, &recordlen,
                                      server_certs,
                                      enc_cert_vector, &enc_cert_vector_len) != 1) {
        return -1;
    }
    tls_trace("<<<< ServerKeyExchange\n");
    if (tlcp_socket_read_server_key_exchange(conn,
                                             record, &recordlen,
                                             &server_certs[0],
                                             enc_cert_vector, enc_cert_vector_len) != 1) {
        return -1;
    }
    // 解析并处理证书请求（如果存在）和服务端Done
    if (tlcp_socket_read_cert_req_server_done(ctx, conn, record, &recordlen, &need_auth) != 1) {
        return -1;
    }

    if (need_auth == 1) {
        // TODO: 客户端身份认证
    }
    tls_trace(">>>> ClientKeyExchange\n");
    if (tlcp_socket_write_client_key_exchange(conn, record, &recordlen, &server_certs[1]) != 1) {
        return -1;
    }
    if (need_auth == 1) {
        // TODO: 证书验证消息
    }
    // 发送客户端 密钥变更和 生成finished
    if (tlcp_socket_write_client_spec_finished(conn, record, &recordlen) != 1) {
        return -1;
    }
    // 接收服务端 密钥变更熊和 验证finished
    if (tlcp_socket_read_server_spec_finished(conn, record, &recordlen) != 1) {
        return -1;
    }
    conn->connected = TLCP_SOCKET_CONNECTED;
    conn->_sm3_ctx  = NULL;
    return 1;
}


/**
 * 断开TLCP连接
 *
 * 关闭连接将会销毁连接过程中所有信息，包括密钥信息。
 *
 * @param conn [in,out] 连接
 */
void TLCP_SOCKET_Connect_Close(TLCP_SOCKET_CONNECT *conn) {
    // 如果连接对象存在，并且socket处于连接状态，那么关闭连接
    if (conn != NULL && conn->sock != 0) {
        if (conn->connected == TLCP_SOCKET_CONNECTED) {
            // TCP socket 由alert内部关闭
            tlcp_socket_alert(conn, TLS_alert_close_notify);
        } else {
            close(conn->sock);
        }
    }
    // 将连接上下文中的工作密钥销毁
    memset(conn, 0, sizeof(*conn));
}

