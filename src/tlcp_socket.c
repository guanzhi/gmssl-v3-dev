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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <gmssl/tlcp_socket.h>
#include <gmssl/tlcp_msg.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>

/**
 * 生成TLCP格式的随机数
 * @param rand 随机源
 * @param random 随机数
 * @return 1
 */
static int tlcp_random_generate(TLCP_SOCKET_RandBytes_FuncPtr rand, uint8_t random[32]) {
    uint32_t gmt_unix_time = (uint32_t) time(NULL);
    uint8_t *p = random;
    size_t len = 0;
    tls_uint32_to_bytes(gmt_unix_time, &p, &len);
    rand(random + 4, 28);
    return 1;
}


int TLCP_listen(TLCP_SOCKET_CTX *ctx, int port) {
    struct sockaddr_in server_addr;
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error_print();
        return -1;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    // 绑定端口，任意来源。
    if (bind(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        error_print();
        return -1;
    }
    error_print_msg(">> start listen port %d", port);
    return TLCP_listen_raw(ctx, sock);
}

int TLCP_listen_raw(TLCP_SOCKET_CTX *ctx, int fd) {
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

void TLCP_close(TLCP_SOCKET_CTX *ctx) {
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
int TLCP_accept(TLCP_SOCKET_CTX *ctx, TLS_CONNECT *conn) {
    size_t handshakes_buflen = 4096;
    uint8_t handshakes_buf[handshakes_buflen];
    uint8_t *handshakes = handshakes_buf;
    size_t handshakeslen = 0;
    uint8_t record[TLS_MAX_RECORD_SIZE];
    size_t recordlen;
    uint8_t finished[256];
    size_t finishedlen = sizeof(finished);

    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t server_enc_cert[TLS_MAX_CERTIFICATES_SIZE];
    size_t server_enc_certlen;

    SM2_KEY client_sign_key;
    SM2_SIGN_CTX sign_ctx;
    uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
    size_t siglen = sizeof(sig);
    uint8_t enced_pms[256];
    size_t enced_pms_len = sizeof(enced_pms);
    uint8_t pre_master_secret[48];
    size_t pre_master_secret_len = 48;
    SM3_CTX sm3_ctx;
    SM3_CTX tmp_sm3_ctx;
    uint8_t sm3_hash[32];
    uint8_t verify_data[12];
    uint8_t local_verify_data[12];
    size_t i;

    struct sockaddr_in client_addr;
    socklen_t client_addrlen = sizeof(client_addr);

    if (ctx == NULL || conn == NULL) {
        error_print();
        return -1;
    }

    memset(conn, 0, sizeof(*conn));
    // 阻塞接收连接
    if ((conn->sock = accept(ctx->_sock, (struct sockaddr *) &client_addr, &client_addrlen)) < 0) {
        error_print();
        return -1;
    }

    sm3_init(&sm3_ctx);
    tls_trace("<<<< ClientHello\n");
    if (read_client_hello(ctx, conn, record, &recordlen, client_random) != 1) {
        return -1;
    }
    update_record_hash(&sm3_ctx, record, recordlen, &handshakes, &handshakeslen);

    tls_trace(">>>> ServerHello\n");
    if (write_server_hello(ctx, conn, record, &recordlen, server_random) != 1) {
        return -1;
    }
    update_record_hash(&sm3_ctx, record, recordlen, &handshakes, &handshakeslen);

    tls_trace(">>>> ServerCertificate\n");
    if (write_server_certificate(ctx, conn, record, &recordlen, server_enc_cert, &server_enc_certlen) != 1) {
        return -1;
    }
    update_record_hash(&sm3_ctx, record, recordlen, &handshakes, &handshakeslen);

    return 1;
}

/**
 * 从TLCP连接中解密校验读取数据
 *
 * @param conn [in] TCLP连接
 * @param buf  [out] 读取数据缓冲区
 * @param len  [out] 读取数据长度
 * @return 1 - 读取成功；-1 - 读取失败
 */
int TLCP_read(TLS_CONNECT *conn, uint8_t *buf, size_t *len);

/**
 * 向TLCP连接中加密验证写入数据
 *
 * @param conn [in] TCLP连接
 * @param data  [in] 读取数据缓冲区
 * @param datalen  [in] 读取数据长度
 * @return 1 - 写入成功；-1 - 写入失败
 */
int TLCP_write(TLS_CONNECT *conn, uint8_t *data, size_t datalen);

/**
 * 连接TLCP服务端
 *
 * @param ctx  [in] 上下文
 * @param conn [out] TLCP连接
 * @return 1 - 连接成功；-1 - 连接失败
 */
int TLCP_connect(TLCP_SOCKET_CTX *ctx, TLS_CONNECT *conn);

/**
 * 断开TLCP连接
 *
 * @param conn [in] 连接
 */
void TLCP_connect_close(TLS_CONNECT *conn) {
    if (conn != NULL) {
        close(conn->sock);
    }
}

