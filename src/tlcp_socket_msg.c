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


int tlcp_socket_read_client_hello(TLCP_SOCKET_CONNECT *conn,
                                  uint8_t *record, size_t *recordlen) {
    size_t i                    = 0;
    int    client_ciphers[12]   = {0};
    size_t client_ciphers_count = sizeof(client_ciphers) / sizeof(client_ciphers[0]);

    // 读取消息
    if (tls_record_recv(record, recordlen, conn->sock) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        tlcp_socket_alert(conn, TLS_alert_protocol_version);
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
    uint8_t tbs[TLS_MAX_CERTIFICATES_SIZE + 64];
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


    if (tls_record_recv(record, recordlen, conn->sock) != 1
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

    uint8_t finished[256];
    size_t  finishedlen = sizeof(finished);
    uint8_t verify_data[12];
    uint8_t local_verify_data[12];
    uint8_t sm3_hash[32];
    SM3_CTX tmp_sm3_ctx;
    tls_trace("<<<< Client CipherSpec\n");
    if (tls_record_recv(record, recordlen, conn->sock) != 1
        || tls_record_version(record) != TLS_version_tlcp) {
        error_print();
        return -1;
    }
    if (tls_record_get_change_cipher_spec(record) != 1) {
        tlcp_socket_alert(conn, TLS_alert_unexpected_message);
        return -1;
    }

    tls_trace("<<<< ClientFinished\n");
    if (tls_record_recv(record, recordlen, conn->sock) != 1
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
    finished[1] = record[1];
    finished[2] = record[2];
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

int tlcp_socket_read_record(TLCP_SOCKET_CONNECT *conn) {
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

int tlcp_socket_write_record(TLCP_SOCKET_CONNECT *conn, const uint8_t *data, size_t datalen) {
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
        case TLS_alert_user_canceled:
            alert_level = TLS_alert_level_warning;
            break;
        case TLS_alert_close_notify:
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
        case TLS_alert_no_renegotiation:
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
    if (tls_record_set_alert(record, &len, alert_level, alert_description) != 1) {
        return;
    }
    if (tls_record_send(record, len, conn->sock) == 1 && alert_level == TLS_alert_level_fatal) {
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
    if (tls_record_recv(record, recordlen, conn->sock) != 1) {
        error_print();
        return -1;
    }
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
    sm3_update(conn->_sm3_ctx, record + 5, *recordlen - 5);
    return 1;
}