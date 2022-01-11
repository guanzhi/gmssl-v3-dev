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
#include <gmssl/tlcp_socket_msg.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <sys/unistd.h>


static const int    tlcp_ciphers[]     = {TLCP_cipher_ecc_sm4_cbc_sm3};
static const size_t tlcp_ciphers_count = sizeof(tlcp_ciphers) / sizeof(tlcp_ciphers[0]);


/**
 * 读取握手消息
 *
 * 读取失败或非握手消息时返回-1
 *
 * @param conn [in] TLCP连接对象
 * @param record [out] 记录层数据
 * @param recordlen [out] 数据长度
 * @return 1 - 成功；-1 - 失败
 */
static int tlcp_socket_read_handshake(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen) {
    if (tls_record_recv(record, recordlen, conn->sock) != 1) {
        return -1;
    }
    // 报警协议部署于握手协议消息
    if (record[0] != TLS_record_handshake) {
        return -1;
    }
    return 1;
}

int tlcp_socket_read_client_hello(TLCP_SOCKET_CONNECT *conn,
                                  uint8_t *record, size_t *recordlen) {
    size_t i                    = 0;
    int    client_ciphers[12]   = {0};
    size_t client_ciphers_count = sizeof(client_ciphers) / sizeof(client_ciphers[0]);

    // 读取消息
    if (tlcp_socket_read_handshake(conn, record, recordlen) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    if (tls_record_get_handshake_client_hello(record, &conn->version, conn->_client_random,
                                              conn->session_id, &conn->session_id_len,
                                              client_ciphers, &client_ciphers_count,
                                              NULL, 0) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    if (conn->version != TLS_version_tlcp) {
        tlcp_socket_alert(conn, TLS_alert_protocol_version);
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
        tlcp_socket_alert(conn, TLS_alert_handshake_failure);
        error_puts("no common cipher_suite");
        return -1;
    }

    conn->entity = TLCP_SOCKET_SERVER_END;
    // 根据算法套件设置密钥长度
    switch (conn->cipher_suite) {
        case TLCP_cipher_ecc_sm4_cbc_sm3:
        default:
            conn->hash_size           = SM3_DIGEST_SIZE;
            conn->key_material_length = SM4_BLOCK_SIZE;
            conn->fixed_iv_length     = SM3_HMAC_SIZE;
            break;
    }
    return 1;
}

int tlcp_socket_write_server_hello(TLCP_SOCKET_CONNECT *conn, TLCP_SOCKET_RandBytes_FuncPtr randFnc,
                                   uint8_t *record, size_t *recordlen) {
    // 生成客户端随机数
    tlcp_socket_random_generate(randFnc, conn->_server_random);
    // 随机产生一个会话ID
    tlcp_socket_random_generate(randFnc, conn->session_id);
    conn->session_id_len = 32;
    if (tls_record_set_handshake_server_hello(record, recordlen,
                                              TLS_version_tlcp, conn->_server_random,
                                              conn->session_id, conn->session_id_len,
                                              conn->cipher_suite, NULL, 0) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    return 1;
}

int tlcp_socket_write_server_certificate(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                         uint8_t *record, size_t *recordlen,
                                         uint8_t *server_enc_cert, size_t *server_enc_certlen) {

    int     type     = TLS_handshake_certificate;
    uint8_t *data    = record + 5 + 4;
    uint8_t *certs   = data + 3;
    size_t  datalen  = 0;
    size_t  certslen = 0;
    uint8_t der[1024];
    uint8_t *cp      = der;
    size_t  derlen   = 0;

    // 序列化签名证书DER
    if (x509_certificate_to_der(ctx->server_sig_key->cert, &cp, &derlen) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    tls_uint24array_to_bytes(der, derlen, &certs, &certslen);

    // 序列化加密证书DER
    cp     = der;
    derlen = 0;
    if (x509_certificate_to_der(ctx->server_enc_key->cert, &cp, &derlen) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
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
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    return 1;
}

int tlcp_socket_random_generate(TLCP_SOCKET_RandBytes_FuncPtr randFnc, uint8_t random[32]) {
    uint32_t gmt_unix_time = (uint32_t) time(NULL);
    uint8_t  *p            = random;
    size_t   len           = 0;
    tls_uint32_to_bytes(gmt_unix_time, &p, &len);
    if (randFnc != NULL) {
        return randFnc(random + 4, 28);
    } else {
        return rand_bytes(random + 4, 28);
    }
}


int tlcp_socket_write_server_key_exchange(TLCP_SOCKET_CONNECT *conn, TLCP_SOCKET_KEY *sig_key,
                                          uint8_t *record, size_t *recordlen,
                                          uint8_t *server_enc_cert, size_t server_enc_certlen) {

    uint8_t sig[TLS_MAX_SIGNATURE_SIZE];
    size_t  siglen = sizeof(sig);
    uint8_t tbs[TLS_MAX_CERTIFICATES_SIZE + 68];
    size_t  len    = 0;
    uint8_t *p     = tbs;

    /*
     * 当密钥交换方式为ECC时，signed_params是服务端对双方随机数和服务端证书的签名
     *
     * digitally-signed struct{
     *      opaque _client_random[32];
     *      opaque _server_random[32];
     *      opaque ASN1.1Cert<1..2^24-1>;
     * }signed_params;
     */
    tls_array_to_bytes(conn->_client_random, 32, &p, &len);
    tls_array_to_bytes(conn->_server_random, 32, &p, &len);
    tls_uint24array_to_bytes(server_enc_cert, server_enc_certlen, &p, &len);

    if (sig_key->signer(sig_key->ctx, tbs, len, sig, &siglen) != 1) {
        error_print();
        return -1;
    }
    if (tlcp_record_set_handshake_server_key_exchange_pke(record, recordlen, sig, siglen) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    return 1;
}

int tlcp_socket_write_server_hello_done(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen) {
    if (tls_record_set_handshake_server_hello_done(record, recordlen) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    return 1;
}

int tlcp_socket_read_client_key_exchange(TLCP_SOCKET_CONNECT *conn, TLCP_SOCKET_KEY *enc_key,
                                         uint8_t *record, size_t *recordlen) {

    uint8_t enced_pms[256];
    uint8_t pre_master_secret[48];
    size_t  enced_pms_len         = sizeof(enced_pms);
    size_t  pre_master_secret_len = 48;
    uint8_t *p                    = NULL;


    if (tlcp_socket_read_handshake(conn, record, recordlen) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    if (tls_record_get_handshake_client_key_exchange_pke(record, enced_pms, &enced_pms_len) != 1) {
        error_print();
        return -1;
    }

    // 解密密钥对
    if (enc_key->decrypter(enc_key->ctx,
                           enced_pms, enced_pms_len,
                           pre_master_secret, &pre_master_secret_len) != 1) {
        tlcp_socket_alert(conn, TLS_alert_decrypt_error);
        return -1;
    }
    // 生成预主密钥
    tls_trace("++++ generate secrets\n");
    if (tls_prf(pre_master_secret, pre_master_secret_len, "master secret",
                conn->_client_random, 32, conn->_server_random, 32,
                48, conn->_master_secret) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    // 生成工作密钥
    if (tls_prf(conn->_master_secret, 48, "key expansion",
                conn->_server_random, 32, conn->_client_random, 32,
                96, conn->_key_block) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    // 切分各个密钥
    p = conn->_key_block;
    // conn->client_write_MAC_secret = _p;
    sm3_hmac_init(&conn->_client_write_mac_ctx, p, conn->hash_size);
    p += conn->hash_size;
    // conn->server_write_MAC_secret = _p;
    sm3_hmac_init(&conn->_server_write_mac_ctx, p, conn->hash_size);
    p += conn->hash_size;
    // conn->client_write_key = _p;
    sm4_set_decrypt_key(&conn->_client_write_enc_key, p);
    p += conn->key_material_length;
    // conn->server_write_key = _p;
    sm4_set_encrypt_key(&conn->_server_write_enc_key, p);

    p += conn->key_material_length;
    conn->_client_write_IV = p;
    p += conn->fixed_iv_length;
    conn->_server_write_IV = p;
//    format_bytes(stderr, 0, 0, "pre_master_secret : ", pre_master_secret, 48);
//    format_bytes(stderr, 0, 0, "_master_secret : ", conn->_master_secret, 48);
//    format_bytes(stderr, 0, 0, "client_write_mac_key : ", conn->_key_block, 32);
//    format_bytes(stderr, 0, 0, "server_write_mac_key : ", conn->_key_block + 32, 32);
//    format_bytes(stderr, 0, 0, "_client_write_enc_key : ", conn->_key_block + 64, 16);
//    format_bytes(stderr, 0, 0, "_server_write_enc_key : ", conn->_key_block + 80, 16);
//    format_print(stderr, 0, 0, "\n");
    return 1;
}

int tlcp_socket_read_client_spec_finished(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen) {

    SM3_CTX tmp_sm3_ctx;
    uint8_t sm3_hash[32]          = {0};
    uint8_t finished[256]         = {0};
    uint8_t verify_data[12]       = {0};
    uint8_t local_verify_data[12] = {0};
    size_t  finishedlen           = sizeof(finished);

    tls_trace("<<<< Client CipherSpec\n");
    if (tls_record_recv(record, recordlen, conn->sock) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        error_print();
        return -1;
    }
    if (tls_record_get_change_cipher_spec(record) != 1) {
        error_print();
        return -1;
    }

    tls_trace("<<<< ClientFinished\n");
    if (tlcp_socket_read_handshake(conn, record, recordlen) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        error_print();
        return -1;
    }
    // 解密客户端Finished消息
    if (tls_record_decrypt(&conn->_client_write_mac_ctx, &conn->_client_write_enc_key,
                           conn->_client_seq_num, record, *recordlen, finished, &finishedlen) != 1) {
        error_print();
        return -1;
    }
    tls_seq_num_incr(conn->_client_seq_num);
    if (tls_record_get_handshake_finished(finished, verify_data) != 1) {
        tlcp_socket_alert(conn, TLS_alert_illegal_parameter);
        return -1;
    }

    memcpy(&tmp_sm3_ctx, conn->_sm3_ctx, sizeof(SM3_CTX));
    sm3_finish(&tmp_sm3_ctx, sm3_hash);

    // 计算校验数据 PRF(_master_secret, finished_label, SM3(handshake_messages))[0..11]
    if (tls_prf(conn->_master_secret, 48, "client finished", sm3_hash, 32, NULL, 0,
                12, local_verify_data) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, finished + 5, finishedlen - 5);

    // 比较数据校验码是否一致
    if (memcmp(local_verify_data, verify_data, 12) != 0) {
        tlcp_socket_alert(conn, TLS_alert_handshake_failure);
        error_puts("client_finished.verify_data verification failure");
        return -1;
    }

    return 1;
}

int tlcp_socket_write_server_spec_finished(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen) {
    uint8_t sm3_hash[32];
    uint8_t verify_data[12];
    uint8_t finished[256];
    size_t  finishedlen = sizeof(finished);

    tls_trace(">>>> [ChangeCipherSpec]\n");
    if (tls_record_set_change_cipher_spec(record, recordlen) != 1) {
        error_print();
        return -1;
    }

    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    // tls_record_print(stderr, record, *recordlen, 0, 0);
    tls_trace(">>>> ServerFinished\n");
    sm3_finish(conn->_sm3_ctx, sm3_hash);
    if (tls_prf(conn->_master_secret, 48, "server finished", sm3_hash, 32, NULL, 0,
                12, verify_data) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    // 创建的缓冲区，需要手动设置协议版本号。
    tls_record_set_version(finished, TLS_version_tlcp);
    if (tls_record_set_handshake_finished(finished, &finishedlen, verify_data) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    // tls_record_print(stderr, finished, finishedlen, 0, 0);
    if (tls_record_encrypt(&conn->_server_write_mac_ctx, &conn->_server_write_enc_key,
                           conn->_server_seq_num, finished, finishedlen, record, recordlen) != 1) {
        error_print();
        return -1;
    }
    tls_seq_num_incr(conn->_server_seq_num);
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    return 1;
}

int tlcp_socket_read_app_data(TLCP_SOCKET_CONNECT *conn) {
    const SM3_HMAC_CTX *hmac_ctx;
    const SM4_KEY      *dec_key;
    uint8_t            *seq_num;
    uint8_t            *crec = conn->_raw_input;  // 密文
    uint8_t            *mrec = conn->record;     // 原文
    size_t             mlen  = sizeof(conn->_raw_input);
    size_t             clen  = sizeof(conn->record);
    int                vers  = 0;

    if (conn->entity == TLCP_SOCKET_CLIENT_END) {
        hmac_ctx = &conn->_server_write_mac_ctx;
        dec_key  = &conn->_server_write_enc_key;
        seq_num  = conn->_server_seq_num;
    } else {
        hmac_ctx = &conn->_client_write_mac_ctx;
        dec_key  = &conn->_client_write_enc_key;
        seq_num  = conn->_client_seq_num;
    }
    tls_trace("<<<< ApplicationData\n");
    if (tls_record_recv(crec, &clen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    // 读写过程中出现报警消息，返回错误
    if (crec[0] == TLS_record_alert) {
        return -1;
    }
    // 解密消息。
    vers = crec[1] << 8 | crec[2];
    if (conn->version != vers
        || tls_record_decrypt(hmac_ctx, dec_key, seq_num, crec, clen, mrec, &mlen) != 1
        || tls_seq_num_incr(seq_num) != 1) {
        error_print();
        return -1;
    }
    // (void) tls_record_print(stderr, mrec, mlen, 0, 0);
    // 向后偏移头部，得到数据部分
    conn->_p          = mrec + 5;
    // 设置剩余长度为除头部分外长度
    conn->_buf_remain = mlen - 5;
    // memcpy(data, mrec + 5, mlen - 5);
    // *datalen = mlen - 5;
    return 1;
}

int tlcp_socket_write_app_data(TLCP_SOCKET_CONNECT *conn, const uint8_t *data, size_t datalen) {
    const SM3_HMAC_CTX *hmac_ctx;
    const SM4_KEY      *enc_key;
    uint8_t            *seq_num;
    uint8_t            mrec[TLCP_SOCKET_DEFAULT_FRAME_SIZE + 8];   // 记录层明文 (头6B)
    uint8_t            crec[TLCP_SOCKET_DEFAULT_FRAME_SIZE + 128];   // 记录层密码文 （头+加密填充和IV+MAC）
    size_t             mlen = sizeof(mrec);
    size_t             clen = sizeof(crec);
    // header 5B; iv 16B; mac 16B; padding 16B
    if (datalen > TLCP_SOCKET_DEFAULT_FRAME_SIZE) {
        error_puts("datalen overflow");
        return -1;
    }

    if (conn->entity == TLCP_SOCKET_CLIENT_END) {
        hmac_ctx = &conn->_client_write_mac_ctx;
        enc_key  = &conn->_client_write_enc_key;
        seq_num  = conn->_client_seq_num;
    } else {
        hmac_ctx = &conn->_server_write_mac_ctx;
        enc_key  = &conn->_server_write_enc_key;
        seq_num  = conn->_server_seq_num;
    }

    tls_trace(">>>> ApplicationData\n");
    if (tls_record_set_version(mrec, conn->version) != 1
        || tls_record_set_application_data(mrec, &mlen, data, datalen) != 1
        || tls_record_encrypt(hmac_ctx, enc_key, seq_num, mrec, mlen, crec, &clen) != 1
        || tls_seq_num_incr(seq_num) != 1
        || tls_record_send(crec, clen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    // (void) tls_record_print(stderr, crec, clen, 0, 0);
    return 1;
}

void tlcp_socket_alert(TLCP_SOCKET_CONNECT *conn, int alert_description) {
    uint8_t record[8];
    size_t  len;
    int     alert_level;
    switch (alert_description) {
        case TLS_alert_close_notify:
        case TLS_alert_user_canceled:
        case TLS_alert_no_renegotiation:
            alert_level = TLS_alert_level_warning;
            break;
        case TLS_alert_unexpected_message:
        case TLS_alert_bad_record_mac:
        case TLS_alert_decryption_failed:
        case TLS_alert_record_overflow:
        case TLS_alert_decompression_failure:
        case TLS_alert_handshake_failure:
        case TLS_alert_no_certificate:
        case TLS_alert_bad_certificate:
        case TLS_alert_unsupported_certificate:
        case TLS_alert_certificate_revoked:
        case TLS_alert_certificate_expired:
        case TLS_alert_certificate_unknown:
        case TLS_alert_illegal_parameter:
        case TLS_alert_unknown_ca:
        case TLS_alert_access_denied:
        case TLS_alert_decode_error:
        case TLS_alert_decrypt_error:
        case TLS_alert_export_restriction:
        case TLS_alert_protocol_version:
        case TLS_alert_insufficient_security:
        case TLS_alert_internal_error:
        case TLS_alert_unsupported_site2site:
        case TLS_alert_no_area:
        case TLS_alert_unsupported_areatype:
        case TLS_alert_bad_ibcparam:
        case TLS_alert_unsupported_ibcparam:
        case TLS_alert_identity_need:
        default:
            alert_level = TLS_alert_level_fatal;
            break;
    }
    record[1] = TLCP_VERSION_MAJOR;
    record[2] = TLCP_VERSION_MINOR;
    // 设置消息
    tls_record_set_alert(record, &len, alert_level, alert_description);
    tls_record_send(record, len, conn->sock);
    // 致命类型的消息关闭连接
    if (alert_level == TLS_alert_level_fatal) {
        //关闭连接
        close(conn->sock);
    }
}

int tlcp_socket_write_client_hello(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                   uint8_t *record, size_t *recordlen) {
    tlcp_socket_random_generate(ctx->rand, conn->_client_random);
    if (tls_record_set_handshake_client_hello(record, recordlen,
                                              TLS_version_tlcp, conn->_client_random, NULL, 0,
                                              tlcp_ciphers, tlcp_ciphers_count, NULL, 0) != 1) {
        error_print();
        return -1;
    }
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);

    return 1;
}

int tlcp_socket_read_server_hello(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen) {
    if (tlcp_socket_read_handshake(conn, record, recordlen) != 1) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    // 检查协议版本
    if (tls_record_version(record) != TLS_version_tlcp) {
        tlcp_socket_alert(conn, TLS_alert_protocol_version);
        return -1;
    }
    if (tls_record_get_handshake_server_hello(record,
                                              &conn->version, conn->_server_random, conn->session_id,
                                              &conn->session_id_len,
                                              &conn->cipher_suite, NULL, 0) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    // 检查协议版本
    if (conn->version != TLS_version_tlcp) {
        tlcp_socket_alert(conn, TLS_alert_protocol_version);
        return -1;
    }
    // 选择密码套件
    if (tls_cipher_suite_in_list(conn->cipher_suite, tlcp_ciphers, tlcp_ciphers_count) != 1) {
        error_print();
        return -1;
    }
    return 1;
}

int tlcp_socket_read_server_certs(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                  uint8_t *record, size_t *recordlen,
                                  X509_CERTIFICATE server_certs[2],
                                  uint8_t *enc_cert_vector, size_t *enc_cert_vector_len) {
    uint8_t          certs_vector[TLS_MAX_CERTIFICATES_SIZE] = {0};
    size_t           certs_vector_len                        = 0;
    const uint8_t    *p                                      = certs_vector;
    const uint8_t    *certs                                  = NULL;
    const uint8_t    *der                                    = NULL;
    size_t           certslen                                = 0;
    size_t           derlen                                  = 0;
    size_t           i                                       = 0;
    X509_CERTIFICATE *sign_cert                              = &server_certs[0];
    X509_CERTIFICATE *enc_cert                               = &server_certs[1];
    X509_CERTIFICATE *ca_cert                                = NULL;

    if (tlcp_socket_read_handshake(conn, record, recordlen) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);

    if (tls_record_get_handshake_certificate(record, certs_vector, &certs_vector_len) != 1) {
        error_print();
        return -1;
    }

    if (tls_uint24array_from_bytes(&certs, &certslen, &p, &certs_vector_len) != 1
        || certs_vector_len > 0) {
        error_print();
        return -1;
    }
    // 解析签名证书
    if (tls_uint24array_from_bytes(&der, &derlen, &certs, &certslen) != 1
        || x509_certificate_from_der(sign_cert, &der, &derlen) != 1
        || derlen > 0) {
        tlcp_socket_alert(conn, TLS_alert_bad_certificate);
        error_print();
        return -1;
    }

    if (tls_uint24array_from_bytes(&der, &derlen, &certs, &certslen) != 1) {
        tlcp_socket_alert(conn, TLS_alert_bad_certificate);
        error_print();
        return -1;
    }
    // 复制加密证书向量，用于验证服务端密钥交换消息
    tls_uint24array_to_bytes(der, derlen, &enc_cert_vector, enc_cert_vector_len);
    // 解析加密证书
    if (x509_certificate_from_der(enc_cert, &der, &derlen) != 1 || derlen > 0) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_bad_certificate);
        return -1;
    }
    if (x509_name_equ(&sign_cert->tbs_certificate.issuer,
                      &enc_cert->tbs_certificate.issuer) != 1) {
        tlcp_socket_alert(conn, TLS_alert_bad_certificate);
        return -1;
    }

    if (certslen) {
        // 如果还有证书，那么忽略后续的证书
    }

    if (ctx->root_certs == NULL || ctx->root_cert_len == 0) {
        // 没有根证书，那么忽略证书的验证
        return 1;
    }

    for (i = 0; i < ctx->root_cert_len; i++) {
        if (x509_name_equ(&ctx->root_certs[i].tbs_certificate.subject, &sign_cert->tbs_certificate.issuer) == 1) {
            ca_cert = &ctx->root_certs[i];
            break;
        }
    }
    // 没有找到匹配的根证书，那么报警
    if (ca_cert == NULL) {
        tlcp_socket_alert(conn, TLS_alert_bad_certificate);
        return -1;
    }
    // 验证签名证书
    if (x509_certificate_verify_by_certificate(sign_cert, ca_cert) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_bad_certificate);
        return -1;
    }

    // 验证加密证书
    if (x509_certificate_verify_by_certificate(enc_cert, ca_cert) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_bad_certificate);
        return -1;
    }
    return 1;
}


int tlcp_socket_read_server_key_exchange(TLCP_SOCKET_CONNECT *conn,
                                         uint8_t *record, size_t *recordlen,
                                         X509_CERTIFICATE *server_sig_cert,
                                         uint8_t *enc_cert_vector, size_t enc_cert_vector_len) {
    uint8_t      sig[TLS_MAX_SIGNATURE_SIZE] = {0};
    size_t       sig_len                     = sizeof(sig);
    SM2_KEY      server_sign_key             = {0};
    SM2_SIGN_CTX verify_ctx                  = {0};


    if (tlcp_socket_read_handshake(conn, record, recordlen) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        tlcp_socket_alert(conn, TLS_alert_handshake_failure);
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    // 解析出签名值
    if (tlcp_record_get_handshake_server_key_exchange_pke(record, sig, &sig_len) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    // 解析签名证书中的公钥
    if (x509_certificate_get_public_key(server_sig_cert, &server_sign_key) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_bad_certificate);
        return -1;
    }

    tls_trace("++++ process ServerKeyExchange\n");
    if (sm2_verify_init(&verify_ctx, &server_sign_key, SM2_DEFAULT_ID) != 1
        || sm2_verify_update(&verify_ctx, conn->_client_random, 32) != 1
        || sm2_verify_update(&verify_ctx, conn->_server_random, 32) != 1
        || sm2_verify_update(&verify_ctx, enc_cert_vector, enc_cert_vector_len) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }

    if (sm2_verify_finish(&verify_ctx, sig, sig_len) != 1) {
        error_puts("ServerKeyExchange signature verification failure");
        tlcp_socket_alert(conn, TLS_alert_handshake_failure);
        return -1;
    }
    return 1;
}

/**
 * 处理证书请求消息，并验证本地证书是否匹配
 *
 * 若本地证书不匹配，那么发出 TLS_alert_no_certificate 错误并关闭连接
 *
 * @param ctx [in] 上下文
 * @param conn [in] 连接上下文
 * @param record [in] 证书请求记录层消息
 * @param recordlen [in] 消息长度
 * @return  1 - 成功；-1 - 失败
 */
static int process_cert_req(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                            uint8_t *record, size_t *recordlen) {

    int    cert_types[TLS_MAX_CERTIFICATE_TYPES];
    size_t cert_types_count;

    uint8_t       ca_names[TLS_MAX_CA_NAMES_SIZE];
    size_t        ca_names_len = 0;
    const uint8_t *cap         = ca_names;
    const uint8_t *dn          = ca_names;
    size_t        dn_len       = 0;

    uint8_t local_dn[256] = {0};
    size_t  local_dn_len  = 0;
    uint8_t *lp           = local_dn;


    tls_trace("<<<< CertificateRequest\n");
    if (tls_record_get_handshake_certificate_request(record,
                                                     cert_types, &cert_types_count,
                                                     ca_names, &ca_names_len) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    // read ServerHelloDone
    if (tlcp_socket_read_handshake(conn, record, recordlen) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);

    // 检查证书、密钥是否存在
    if (ctx->client_sig_key == NULL || ctx->client_sig_key->cert == NULL) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_no_certificate);
        return -1;
    }
    // 解析当前签名证书信息
    if (x509_name_to_der(&ctx->client_sig_key->cert->tbs_certificate.issuer, &lp, &local_dn_len) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    // 查找与本地证书匹配的 服务器证书
    do {
        if (tls_uint16array_from_bytes(&dn, &dn_len, &cap, &ca_names_len) != 1) {
            // 无法解析  DN
            return -1;
        }
        if (local_dn_len != dn_len) {
            return -1;
        }
        if (memcmp(dn, local_dn, dn_len) == 0) {
            return 1;
        }
    } while (ca_names_len > 0);

    return -1;
}

int tlcp_socket_read_cert_req_server_done(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                          uint8_t *record, size_t *recordlen,
                                          uint8_t *need_auth) {

    int           type;
    const uint8_t *data;
    size_t        data_len;

    if (tlcp_socket_read_handshake(conn, record, recordlen) != 1
        || tls_record_version(record) != TLS_version_tlcp
        || tls_record_get_handshake(record, &type, &data, &data_len) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    // 判断消息是否为证书请求
    if (type == TLS_handshake_certificate_request) {
        // 处理证书请求消息，并验证本地证书是否匹配
        if (process_cert_req(ctx, conn, record, recordlen) != 1) {
            return -1;
        }
        // 需要客户端认证
        *need_auth = 1;
    }
    tls_trace("<<<< ServerHelloDone\n");
    if (tls_record_get_handshake_server_hello_done(record) != 1) {
        error_print();
        return -1;
    }

    return 1;
}

int tlcp_socket_write_client_key_exchange(TLCP_SOCKET_CONNECT *conn,
                                          uint8_t *record, size_t *recordlen,
                                          X509_CERTIFICATE *server_enc_cert) {
    SM2_KEY server_enc_key               = {0};
    uint8_t pre_master_secret[48]        = {0};
    uint8_t enced_pre_master_secret[256] = {0};
    size_t  enced_pre_master_secret_len  = {0};

    if (tls_pre_master_secret_generate(pre_master_secret, TLS_version_tlcp) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    // 解析加密证书中的公钥
    if (x509_certificate_get_public_key(server_enc_cert, &server_enc_key) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_bad_certificate);
        return -1;
    }
    // 使用加密证书中的公钥加密预主密钥
    if (sm2_encrypt(&server_enc_key, pre_master_secret, 48,
                    enced_pre_master_secret, &enced_pre_master_secret_len) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    if (tls_record_set_handshake_client_key_exchange_pke(record, recordlen,
                                                         enced_pre_master_secret, enced_pre_master_secret_len) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);

    tls_trace("++++ generate secrets\n");
    if (tls_prf(pre_master_secret, 48, "master secret",
                conn->_client_random, 32, conn->_server_random, 32,
                48, conn->_master_secret) != 1
        || tls_prf(conn->_master_secret, 48, "key expansion",
                   conn->_server_random, 32, conn->_client_random, 32,
                   96, conn->_key_block) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    sm3_hmac_init(&conn->_client_write_mac_ctx, conn->_key_block, 32);
    sm3_hmac_init(&conn->_server_write_mac_ctx, conn->_key_block + 32, 32);
    sm4_set_encrypt_key(&conn->_client_write_enc_key, conn->_key_block + 64);
    sm4_set_decrypt_key(&conn->_server_write_enc_key, conn->_key_block + 80);
    conn->_client_write_IV = conn->_key_block + 96;
    conn->_server_write_IV = conn->_key_block + 112;
//    format_bytes(stderr, 0, 0, "pre_master_secret : ", pre_master_secret, 48);
//    format_bytes(stderr, 0, 0, "master_secret : ", conn->master_secret, 48);
//    format_bytes(stderr, 0, 0, "client_write_mac_key : ", conn->key_block, 32);
//    format_bytes(stderr, 0, 0, "server_write_mac_key : ", conn->key_block + 32, 32);
//    format_bytes(stderr, 0, 0, "client_write_enc_key : ", conn->key_block + 64, 16);
//    format_bytes(stderr, 0, 0, "server_write_enc_key : ", conn->key_block + 80, 16);
//    format_print(stderr, 0, 0, "\n");

    return 1;
}


int tlcp_socket_write_client_spec_finished(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen) {
    SM3_CTX tmp_sm3_ctx;
    uint8_t sm3_hash[32];
    uint8_t verify_data[12];
    uint8_t finished[256];
    size_t  finishedlen;

    tls_trace(">>>> [ChangeCipherSpec]\n");
    if (tls_record_set_change_cipher_spec(record, recordlen) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    // tls_record_print(stderr, record, recordlen, 0, 0);

    tls_trace(">>>> Finished\n");
    memcpy(&tmp_sm3_ctx, conn->_sm3_ctx, sizeof(SM3_CTX));
    sm3_finish(&tmp_sm3_ctx, sm3_hash);

    if (tls_prf(conn->_master_secret, 48, "client finished",
                sm3_hash, 32, NULL, 0,
                sizeof(verify_data), verify_data) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    // 设置缓冲区消息的协议版本号
    tls_record_set_version(finished, TLS_version_tlcp);
    if (tls_record_set_handshake_finished(finished, &finishedlen, verify_data) != 1) {
        error_print();
        return -1;
    }
    // tls_record_print(stderr, finished, finishedlen, 0, 0);
    sm3_update(conn->_sm3_ctx, finished + 5, finishedlen - 5);

    if (tls_record_encrypt(&conn->_client_write_mac_ctx, &conn->_client_write_enc_key,
                           conn->_client_seq_num, finished, finishedlen, record, recordlen) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_decode_error);
        return -1;
    }
    tls_seq_num_incr(conn->_client_seq_num);
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    return 1;
}

int tlcp_socket_read_server_spec_finished(TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen) {
    uint8_t verify_data[12]       = {0};
    uint8_t local_verify_data[12] = {0};
    uint8_t sm3_hash[32]          = {0};
    uint8_t finished[256]         = {0};
    size_t  finishedlen;
    // 设置缓冲区消息的协议版本号
    tls_record_set_version(finished, TLS_version_tlcp);

    tls_trace("<<<< [ChangeCipherSpec]\n");
    if (tls_record_recv(record, recordlen, conn->sock) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_handshake_failure);
        return -1;
    }
    if (tls_record_get_change_cipher_spec(record) != 1) {
        error_print();
        return -1;
    }

    tls_trace("<<<< Finished\n");
    if (tlcp_socket_read_handshake(conn, record, recordlen) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_handshake_failure);
        return -1;
    }
    // 解密finished消息
    if (tls_record_decrypt(&conn->_server_write_mac_ctx, &conn->_server_write_enc_key,
                           conn->_server_seq_num, record, *recordlen, finished, &finishedlen) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    tls_seq_num_incr(conn->_server_seq_num);
    // 获取finished消息中的 验证数据 verify_data
    if (tls_record_get_handshake_finished(finished, verify_data) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_handshake_failure);
        return -1;
    }
    // 通过计算之前的消息，生成本地的验证数据
    sm3_finish(conn->_sm3_ctx, sm3_hash);
    if (tls_prf(conn->_master_secret, 48, "server finished",
                sm3_hash, 32, NULL, 0,
                sizeof(local_verify_data), local_verify_data) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    if (memcmp(local_verify_data, verify_data, 12) != 0) {
        error_puts("server_finished.verify_data verification failure");
        tlcp_socket_alert(conn, TLS_alert_handshake_failure);
        return -1;
    }

    tls_trace("++++ Connection established\n");
    return 1;
}


int tlcp_socket_write_client_certificate(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                         uint8_t *record, size_t *recordlen) {

    int     type     = TLS_handshake_certificate;
    uint8_t *data    = record + 5 + 4;
    uint8_t *certs   = data + 3;
    size_t  datalen  = 0;
    size_t  certslen = 0;
    uint8_t der[1024];
    uint8_t *cp      = der;
    size_t  derlen   = 0;

    // 序列化签名证书DER
    if (x509_certificate_to_der(ctx->client_sig_key->cert, &cp, &derlen) != 1) {
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        error_print();
        return -1;
    }
    tls_uint24array_to_bytes(der, derlen, &certs, &certslen);

    datalen = certslen;
    tls_uint24_to_bytes((uint24_t) certslen, &data, &datalen);
    tls_record_set_handshake(record, recordlen, type, NULL, datalen);
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    return 1;
}

int tlcp_socket_write_client_cert_verify(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn,
                                         uint8_t *record, size_t *recordlen) {
    SM3_CTX         tmp_sm3_ctx;
    TLCP_SOCKET_KEY *sig_key                               = ctx->client_sig_key;
    uint8_t         sig[TLS_MAX_SIGNATURE_SIZE]            = {0};
    size_t          siglen                                 = sizeof(sig);
    uint8_t         msg[SM3_DIGEST_SIZE]                   = {0};
    uint8_t         sig_vector[TLS_MAX_SIGNATURE_SIZE + 2] = {0};           // 签名向量
    uint8_t         *p                                     = sig_vector;    // 向量指针
    size_t          sig_vector_len                         = 0;


    memcpy(&tmp_sm3_ctx, conn->_sm3_ctx, sizeof(SM3_CTX));
    sm3_finish(&tmp_sm3_ctx, msg);
    /*
     * from GBT38636 6.4.5.6
     *
     * case ecc_sm3: // 当ECC为SM2算法时，用这个套件
     *  digitally-signed struct{
     *      opaque sm3_hash[32];
     *  }
     * sm3_hash 是指hash运行的结果，运算的内容时客户端hello消息开始
     * 直到本消息（不包括本消息）的所有与握手有关的消息，包括握手消息
     * 的类型和长度域。
     */
    if (sig_key->signer(sig_key->ctx, msg, SM3_DIGEST_SIZE, sig, &siglen) != 1) {
        error_puts("client signature fail");
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    // 签名值是一个向量
    tls_uint16array_to_bytes(sig, siglen, &p, &sig_vector_len);
    if (tls_record_set_handshake_certificate_verify(record, recordlen, sig_vector, sig_vector_len) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }
    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    return 1;
}

int tlcp_socket_write_cert_req(TLCP_SOCKET_CTX *ctx, TLCP_SOCKET_CONNECT *conn, uint8_t *record, size_t *recordlen) {
    const int cert_types[]                    = {TLS_cert_type_ecdsa_sign,};
    uint8_t   ca_names[TLS_MAX_CA_NAMES_SIZE] = {0};
    size_t    cert_types_count                = sizeof(cert_types) / sizeof(cert_types[0]);
    size_t    ca_names_len                    = 0;

    uint8_t *p           = ca_names;
    size_t  i            = 0;
    uint8_t dn_item[256] = {0};
    size_t  dn_item_len  = 0;
    uint8_t *p_dn        = dn_item;

    // 构造服务端信任的CA证书DN列表，也就是根证书Subject列表
    for (i = 0; i < ctx->root_cert_len; i++) {
        p_dn        = dn_item;
        dn_item_len = 0;
        // 解析根证数中的subject DN为DER格式
        if (x509_name_to_der(&ctx->root_certs[i].tbs_certificate.subject, &p_dn, &dn_item_len) != 1) {
            // 忽略证书无法解析的情况
            continue;
        }
        if (ca_names_len + (2 + dn_item_len) > TLS_MAX_CA_NAMES_SIZE ){
            // 超过最大能容纳数量，忽略后续的证书
            break;
        }
        tls_uint16array_to_bytes(dn_item, dn_item_len, &p, &ca_names_len);
    }

    if (tls_record_set_handshake_certificate_request(record, recordlen,
                                                     cert_types, cert_types_count,
                                                     ca_names, ca_names_len) != 1) {
        error_print();
        tlcp_socket_alert(conn, TLS_alert_internal_error);
        return -1;
    }

    if (tls_record_send(record, *recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    return 1;
}