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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/oid.h>
#include <gmssl/sm2.h>
#include <gmssl/pem.h>
#include <gmssl/error.h>
#include <gmssl/hex.h>


static int test_sm2_point_octets(void) {
    int       err = 0;
    SM2_KEY   sm2_key;
    SM2_POINT point;
    uint8_t   buf[65];
    int       i;

    // compress
    for (i = 0; i < 8; i++) {
        uint8_t buf[33];
        sm2_keygen(&sm2_key);
        sm2_point_to_compressed_octets(&sm2_key.public_key, buf);
        if (sm2_point_from_octets(&point, buf, sizeof(buf)) != 1) {
            error_print();
            err++;
            break;
        }
        if (memcmp(&sm2_key.public_key, &point, sizeof(SM2_POINT)) != 0) {
            error_print();
            err++;
            break;
        }
    }

    // uncompress
    for (i = 0; i < 8; i++) {
        uint8_t buf[65];
        sm2_keygen(&sm2_key);
        sm2_point_to_uncompressed_octets(&sm2_key.public_key, buf);
        if (sm2_point_from_octets(&point, buf, sizeof(buf)) != 1) {
            error_print();
            err++;
            break;
        }
        if (memcmp(&sm2_key.public_key, &point, sizeof(SM2_POINT)) != 0) {
            error_print();
            err++;
            break;
        }
    }

    printf("%s : %s\n", __func__, err ? "failed" : "ok");
    return err;
}

static int test_sm2_private_key(void) {
    int           err = 0;
    SM2_KEY       sm2_key;
    SM2_KEY       sm2_tmp;
    uint8_t       buf[256];
    uint8_t       *p  = buf;
    const uint8_t *cp = buf;
    size_t        len = 0;


    sm2_keygen(&sm2_key);

    if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1) {
        error_print();
        err++;
        goto end;
    }
    if (sm2_private_key_from_der(&sm2_tmp, &cp, &len) != 1
        || len > 0) {
        error_print();
        err++;
        goto end;
    }
    // 比较密钥字段移除密钥用法部分
    if (memcmp(&sm2_tmp, &sm2_key, sizeof(SM2_KEY)-4) != 0) {
        error_print();
        err++;
        goto end;
    }

    printf("%s : ok\n", __func__);
    end:
    return err;
}

static int test_sm2_public_key_info(void) {
    int           err = 0;
    SM2_KEY       sm2_key;
    SM2_KEY       sm2_tmp;
    uint8_t       buf[256];
    uint8_t       *p  = buf;
    const uint8_t *cp = buf;
    size_t        len = 0;

    sm2_keygen(&sm2_key);

    if (sm2_public_key_info_to_der(&sm2_key, &p, &len) != 1) {
        error_print();
        err++;
        goto end;
    }
    if (sm2_public_key_info_from_der(&sm2_tmp, &cp, &len) != 1
        || len > 0) {
        error_print();
        err++;
        goto end;
    }
    if (memcmp(&sm2_key.public_key, &sm2_tmp.public_key, sizeof(SM2_POINT)) != 0) {
        error_print();
        err++;
        goto end;
    }
    printf("%s : ok\n", __func__);
    end:
    return err;
}

static void test_sm2_parse_pkcs8__private_key(void) {
    uint8_t       str[] = "-----BEGIN EC PRIVATE KEY-----\n\
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgmfgsjOI+jhOcwu7f\n\
Cy6PYSYBmjAzTijLaJicJorUEsmgCgYIKoEcz1UBgi2hRANCAAQJTFguoSNb/TEX\n\
XwY1w3Xw+79W3YFg3JWQlJVx2FZmzWuT8x6aIeiciv0wuwuaYfocUC3OHwkRKqhf\n\
CkPArdH2\n\
-----END EC PRIVATE KEY-----";
    uint8_t       buf[1024];
    const uint8_t *cp   = buf;
    size_t        len   = 0;
    SM2_KEY       key;

    if (pem_read_str(str, strlen(str), "EC PRIVATE KEY", buf, &len) != 1) {
        error_puts("无法解析PEM");
        goto end;
    }

    if (sm2_private_key_from_pkcs8_der(&key, &cp, &len) != 1) {
        error_puts("PKCS8解码失败");
        goto end;
    }
    printf("%s : ok\n", __func__);
    end:
    return;
}

static void test_sm2_ciphertext_to_der() {
    // X 长度不足32字节，含有前置一个字节的00
    uint8_t x_str[]      = "00ABD5FD079006A141C605B44455027B311B453E3A24FEDD16B5446C83567B99";
    // Y 32字节元素
    uint8_t y_str[]      = "B8ACFE0E01D5E8B1513F32E29F6A6B0CEA967CC6ED3860EE4A5A4785EBC32D47";
    uint8_t expect_str[] = "\
3069022000ABD5FD079006A141C605B44455027B311B453E3A24FEDD16B5446C\
83567B99022100B8ACFE0E01D5E8B1513F32E29F6A6B0CEA967CC6ED3860EE4A\
5A4785EBC32D4704200000000000000000000000000000000000000000000000\
0000000000000000000400";

    int            i    = 0;
    size_t         clen = SM2_CIPHERTEXT_SIZE(32);
    size_t         cbuf[clen];
    SM2_CIPHERTEXT *c   = (SM2_CIPHERTEXT *) cbuf;


    memset(cbuf, 0, clen);

    uint8_t expect[128] = {0};
    uint8_t out[256]    = {0};
    size_t  outlen      = 0;
    uint8_t *p          = out;

    hex2bin(x_str, strlen(x_str), c->point.x);
    hex2bin(y_str, strlen(y_str), c->point.y);
    hex2bin(expect_str, strlen(expect_str), expect);

    sm2_ciphertext_to_der(c, &p, &outlen);

    if (memcmp(out, expect, outlen) != 0) {
        printf("Expect:\n");
        print_bytes(expect, outlen);
        printf("Actual:\n");
        print_bytes(out, outlen);
    } else {
        printf("%s : ok\n", __func__);
    }

}

int main(void) {
    test_sm2_point_octets();
    test_sm2_private_key();
    test_sm2_public_key_info();
    test_sm2_parse_pkcs8__private_key();
    test_sm2_ciphertext_to_der();
    return 0;
}



