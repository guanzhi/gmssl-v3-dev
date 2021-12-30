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

#include <gmssl/tlcp_socket.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


static const int    tlcp_ciphers[]     = {TLCP_cipher_ecc_sm4_cbc_sm3};
static const size_t tlcp_ciphers_count = sizeof(tlcp_ciphers) / sizeof(tlcp_ciphers[0]);

int update_record_hash(SM3_CTX *sm3_ctx,
                       uint8_t *record, size_t recordlen,
                       uint8_t **handshakes, size_t *handshakeslen) {
    sm3_update(sm3_ctx, record + 5, recordlen - 5);
    if (handshakes) {
        memcpy(*handshakes, record + 5, recordlen - 5);
        (*handshakes) += recordlen - 5;
        (*handshakeslen) += recordlen - 5;
    }
}

int read_client_hello(TLCP_SOCKET_CTX *ctx, TLS_CONNECT *conn,
                      uint8_t *record, size_t *recordlen, uint8_t *client_random) {
    size_t i                    = 0;
    int    client_ciphers[12]   = {0};
    size_t client_ciphers_count = sizeof(client_ciphers) / sizeof(client_ciphers[0]);

    // 读取消息
    if (tls_record_recv(record, recordlen, conn->sock) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        tlcp_alert(TLS_alert_protocol_version, conn->sock);
        error_print();
        return -1;
    }

    if (tls_record_get_handshake_client_hello(record, &conn->version, client_random,
                                              conn->session_id, &conn->session_id_len,
                                              client_ciphers, &client_ciphers_count,
                                              NULL, 0) != 1) {
        tlcp_alert(TLS_alert_internal_error, conn->sock);
        error_print();
        return -1;
    }
    if (conn->version != TLS_version_tlcp) {
        tlcp_alert(TLS_alert_protocol_version, conn->sock);
        error_print();
        return -1;
    }
    // 取出兼容的密码套件
    for (i = 0; i < tlcp_ciphers_count; i++) {
        if (tls_cipher_suite_in_list(tlcp_ciphers[i], client_ciphers, client_ciphers_count) == 1) {
            conn->cipher_suite = tlcp_ciphers[i];
            break;
        }
    }
    if (conn->cipher_suite == 0) {
        tlcp_alert(TLS_alert_handshake_failure, conn->sock);
        error_puts("no common cipher_suite");
        return -1;
    }
    return 1;
}

int write_server_hello(TLCP_SOCKET_CTX *ctx, TLS_CONNECT *conn,
                       uint8_t *record, size_t *recordlen, uint8_t *server_random) {
    // 生成客户端随机数
    tls_random_generate(server_random);
    // 随机产生一个会话ID
    tls_random_generate(conn->session_id);
    conn->session_id_len = 32;
    if (tls_record_set_handshake_server_hello(record, recordlen,
                                              TLS_version_tlcp,
                                              server_random, conn->session_id, conn->session_id_len,
                                              conn->cipher_suite, NULL, 0) != 1) {
        tlcp_alert(TLS_alert_internal_error, conn->sock);
        error_print();
        return -1;
    }
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    return 1;
}

int write_server_certificate(TLCP_SOCKET_CTX *ctx, TLS_CONNECT *conn,
                             uint8_t *record, size_t *recordlen,
                             uint8_t *server_enc_cert, size_t *server_enc_certlen) {

    int     type     = TLS_handshake_certificate;
    uint8_t *data    = record + 5 + 4;
    uint8_t *certs   = data + 3;
    size_t  datalen  = 0;
    size_t  certslen = 0;
    uint8_t der[1024];
    uint8_t *cp      = der;
    size_t  derlen;

    // 序列化签名证书DER
    if (x509_certificate_to_der(ctx->server_sig_key->cert, &cp, &derlen) != 1) {
        tlcp_alert(TLS_alert_internal_error, ctx->_sock);
        error_print();
        return -1;
    }
    memcpy(conn->server_certs, der, derlen);
    tls_uint24array_to_bytes(der, derlen, &certs, &certslen);

    // 序列化加密证书DER
    cp     = der;
    derlen = 0;
    if (x509_certificate_to_der(ctx->server_enc_key->cert, &cp, &derlen) != 1) {
        tlcp_alert(TLS_alert_internal_error, ctx->_sock);
        error_print();
        return -1;
    }
    memcpy(server_enc_cert, der, derlen);
    *server_enc_certlen = derlen;
    tls_uint24array_to_bytes(der, derlen, &certs, &certslen);


    datalen = certslen;
    tls_uint24_to_bytes((uint24_t) certslen, &data, &datalen);
    tls_record_set_handshake(record, recordlen, type, NULL, datalen);
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }

    return 1;
}