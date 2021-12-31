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
#include <gmssl/error.h>
#include <gmssl/sm2.h>


/**
 * 【私有】 基于国密SSL SM2私钥的签名接口实现
 * @param ctx [in] SM2_KEY指针
 * @param msg [in] 待签名消息
 * @param msglen [in]消息长度
 * @param sig [out] 签名值
 * @param siglen [out] 签名值长度
 * @return 1 - 连接成功；-1 - 连接失败
 */
static int gmssl_sm2_signer(void *ctx, uint8_t *msg, size_t msglen, uint8_t *sig, size_t *siglen);


/**
 * 【私有】 基于国密SSL SM2私钥的解密接口实现
 *
 * @param ctx             [in] SM2_KEY指针
 * @param ciphertext      [in] 密文
 * @param ciphertext_len  [in] 密文长度
 * @param plaintext       [out] 明文
 * @param plaintext_len   [out] 明文长度
 * @return 1 - 成功；-1 - 失败
 */
static int gmssl_sm2_decrypter(void *ctx, uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t *plaintext, size_t *plaintext_len);

int TLCP_SOCKET_gmssl_key(TLCP_SOCKET_KEY *socket_key, X509_CERTIFICATE *cert, SM2_KEY *sm2_key) {
    if (sm2_key == NULL || cert == NULL || socket_key == NULL) {
        error_print();
        return -1;
    }

    socket_key->ctx       = sm2_key;
    socket_key->cert      = cert;
    socket_key->signer    = gmssl_sm2_signer;
    socket_key->decrypter = gmssl_sm2_decrypter;
    return 1;
}

static int gmssl_sm2_signer(void *ctx, uint8_t *msg, size_t msglen, uint8_t *sig, size_t *siglen) {
    SM2_SIGN_CTX sign_ctx;
    if (sm2_sign_init(&sign_ctx, (SM2_KEY *) ctx, SM2_DEFAULT_ID) != 1) {
        error_print();
        return -1;
    }
    if (sm2_sign_update(&sign_ctx, msg, msglen) != 1) {
        error_print();
        return -1;
    }
    if (sm2_sign_finish(&sign_ctx, sig, siglen) != 1) {
        error_print();
        return -1;
    }
    return 1;
}

static int gmssl_sm2_decrypter(void *ctx, uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t *plaintext, size_t *plaintext_len) {
    return sm2_decrypt((SM2_KEY *) ctx, ciphertext, ciphertext_len,
                       plaintext, plaintext_len);
}