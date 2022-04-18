/*
 * Copyright (c) 2016 - 2021 The GmSSL Project.  All rights reserved.
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

#ifndef GMSSL_SM9_H
#define GMSSL_SM9_H

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t sm9_bn_t[8];
typedef sm9_bn_t sm9_fp_t;
typedef sm9_bn_t sm9_fn_t;
typedef uint64_t sm9_barrett_bn_t[9];
typedef sm9_fp_t sm9_fp2_t[2];
typedef sm9_fp2_t sm9_fp4_t[2];
typedef sm9_fp4_t sm9_fp12_t[3];


static const sm9_bn_t SM9_ZERO  = {0,0,0,0,0,0,0,0};
static const sm9_bn_t SM9_ONE   = {1,0,0,0,0,0,0,0};
static const sm9_bn_t SM9_TWO   = {2,0,0,0,0,0,0,0};
static const sm9_bn_t SM9_FIVE  = {5,0,0,0,0,0,0,0};

// p =  b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d
// n =  b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25
// mu = 2^512 // p = 167980e0beb5759a655f73aebdcd1312af2665f6d1e36081c71188f90d5c22146
static const sm9_bn_t SM9_P = {0xe351457d, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
static const sm9_bn_t SM9_P_MINUS_ONE = {0xe351457c, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
static const sm9_bn_t SM9_N = {0xd69ecf25, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000};
static const sm9_bn_t SM9_MU = {0xd5c22146, 0x71188f90, 0x1e36081c, 0xf2665f6d, 0xdcd1312a, 0x55f73aeb, 0xeb5759a6, 0x167980e0b};

typedef struct {
	sm9_fp_t X;
	sm9_fp_t Y;
	sm9_fp_t Z;
} sm9_point_t;

// P1.X 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
// P1.Y 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616
static const sm9_point_t _SM9_P1 = {
	{0x7c66dddd, 0xe8c4e481, 0x09dc3280, 0xe1e40869, 0x487d01d6, 0xf5ed0704, 0x62bf718f, 0x93de051d},
	{0x0a3ea616, 0x0c464cd7, 0xfa602435, 0x1c1c00cb, 0x5c395bbc, 0x63106512, 0x4f21e607, 0x21fe8dda},
	{1,0,0,0,0,0,0,0}
};
static const sm9_point_t *SM9_P1 = &_SM9_P1;

typedef struct {
	sm9_fp2_t X;
	sm9_fp2_t Y;
	sm9_fp2_t Z;
} sm9_twist_point_t;

/*
	X : [0x3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65bn,
	     0x85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141n],
	Y : [0xa7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7n,
	     0x17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96n],
	Z : [1n, 0n],
*/
static const sm9_twist_point_t _SM9_P2 = {
	{{0xAF82D65B, 0xF9B7213B, 0xD19C17AB, 0xEE265948, 0xD34EC120, 0xD2AAB97F, 0x92130B08, 0x37227552},
	 {0xD8806141, 0x54806C11, 0x0F5E93C4, 0xF1DD2C19, 0xB441A01F, 0x597B6027, 0x78640C98, 0x85AEF3D0}},
	{{0xC999A7C7, 0x6215BBA5, 0xA71A0811, 0x47EFBA98, 0x3D278FF2, 0x5F317015, 0x19BE3DA6, 0xA7CF28D5},
	 {0x84EBEB96, 0x856DC76B, 0xA347C8BD, 0x0736A96F, 0x2CBEE6ED, 0x66BA0D26, 0x2E845C12, 0x17509B09}},
	{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
};
static const sm9_twist_point_t *SM9_P2 = &_SM9_P2;



static const sm9_twist_point_t _SM9_Ppubs = {
	{{0x96EA5E32, 0x8F14D656, 0x386A92DD, 0x414D2177, 0x24A3B573, 0x6CE843ED, 0x152D1F78, 0x29DBA116},
	 {0x1B94C408, 0x0AB1B679, 0x5E392CFB, 0x1CE0711C, 0x41B56501, 0xE48AFF4B, 0x3084F733, 0x9F64080B}},
	{{0xB4E3216D, 0x0E75C05F, 0x5CDFF073, 0x1006E85F, 0xB7A46F74, 0x1A7CE027, 0xDDA532DA, 0x41E00A53},
         {0xD0EF1C25, 0xE89E1408, 0x1A77F335, 0xAD3E2FDB, 0x47E3A0CB, 0xB57329F4, 0xABEA0112, 0x69850938}},
	{{1,0,0,0,0,0,0,0}, {0,0,0,0,0,0,0,0}},
};
static const sm9_twist_point_t *SM9_Ppubs = &_SM9_Ppubs;




#define sm9_bn_init(r)		memset((r),0,sizeof(sm9_bn_t))
#define sm9_bn_clean(r)		memset((r),0,sizeof(sm9_bn_t))
#define sm9_bn_set_zero(r)	memset((r),0,sizeof(sm9_bn_t))
#define sm9_bn_set_one(r)	memcpy((r),&SM9_ONE,sizeof(sm9_bn_t))
#define sm9_bn_copy(r,a)	memcpy((r),(a),sizeof(sm9_bn_t))
#define sm9_bn_is_zero(a)	(memcmp((a),&SM9_ZERO, sizeof(sm9_bn_t)) == 0)
#define sm9_bn_is_one(a)	(memcmp((a),&SM9_ONE, sizeof(sm9_bn_t)) == 0)

static void sm9_bn_to_bytes(const sm9_bn_t a, uint8_t out[32]);

static void sm9_bn_from_bytes(sm9_bn_t r, const uint8_t in[32]);

static int sm9_bn_from_hex(sm9_bn_t r, const char hex[65]);

static void sm9_bn_to_hex(const sm9_bn_t a, char hex[65]);

static void sm9_print_bn(const char *prefix, const sm9_bn_t a);

static void sm9_bn_to_bits(const sm9_bn_t a, char bits[256]);

static int sm9_bn_cmp(const sm9_bn_t a, const sm9_bn_t b);

static int sm9_bn_equ_hex(const sm9_bn_t a, const char *hex);

static void sm9_bn_set_word(sm9_bn_t r, uint32_t a);

static void sm9_bn_add(sm9_bn_t r, const sm9_bn_t a, const sm9_bn_t b);

static void sm9_bn_sub(sm9_bn_t ret, const sm9_bn_t a, const sm9_bn_t b);

static void sm9_bn_rand_range(sm9_bn_t r, const sm9_bn_t range);

#define sm9_fp_init(a)		sm9_bn_init(a)
#define sm9_fp_clean(a)		sm9_bn_clean(a)
#define sm9_fp_is_zero(a)	sm9_bn_is_zero(a)
#define sm9_fp_is_one(a)	sm9_bn_is_one(a)
#define sm9_fp_set_zero(a)	sm9_bn_set_zero(a)
#define sm9_fp_set_one(a)	sm9_bn_set_one(a)
#define sm9_fp_from_hex(a,s) 	sm9_bn_from_hex((a),(s))
#define sm9_fp_to_hex(a,s)	sm9_bn_to_hex((a),(s))
#define sm9_fp_copy(r,a)	sm9_bn_copy((r),(a))

static int sm9_fp_equ(const sm9_fp_t a, const sm9_fp_t b);

static void sm9_fp_add(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b);

static void sm9_fp_sub(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b);

static void sm9_fp_dbl(sm9_fp_t r, const sm9_fp_t a);

static void sm9_fp_tri(sm9_fp_t r, const sm9_fp_t a);

static void sm9_fp_div2(sm9_fp_t r, const sm9_fp_t a);

static void sm9_fp_neg(sm9_fp_t r, const sm9_fp_t a);

static int sm9_barrett_bn_cmp(const sm9_barrett_bn_t a, const sm9_barrett_bn_t b);

static void sm9_barrett_bn_add(sm9_barrett_bn_t r, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b);

static void sm9_barrett_bn_sub(sm9_barrett_bn_t ret, const sm9_barrett_bn_t a, const sm9_barrett_bn_t b);

static void sm9_fp_mul(sm9_fp_t r, const sm9_fp_t a, const sm9_fp_t b);

static void sm9_fp_sqr(sm9_fp_t r, const sm9_fp_t a);

static void sm9_fp_pow(sm9_fp_t r, const sm9_fp_t a, const sm9_bn_t e);

static void sm9_fp_inv(sm9_fp_t r, const sm9_fp_t a);


static const sm9_fp2_t SM9_FP2_ZERO = {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}};
static const sm9_fp2_t SM9_FP2_ONE  = {{1,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}};
static const sm9_fp2_t SM9_FP2_U    = {{0,0,0,0,0,0,0,0},{1,0,0,0,0,0,0,0}};
static const sm9_fp2_t SM9_FP2_5U    = {{0,0,0,0,0,0,0,0},{5,0,0,0,0,0,0,0}};


#define sm9_fp2_init(a)		memset((a), 0, sizeof(sm9_fp2_t))
#define sm9_fp2_clean(a)	memset((a), 0, sizeof(sm9_fp2_t))
#define sm9_fp2_is_zero(a)	(memcmp((a), &SM9_FP2_ZERO, sizeof(sm9_fp2_t)) == 0)
#define sm9_fp2_is_one(a)	(memcmp((a), &SM9_FP2_ONE, sizeof(sm9_fp2_t)) == 0)
#define sm9_fp2_copy(r,a)	memcpy((r), (a), sizeof(sm9_fp2_t))
#define sm9_fp2_equ(a,b)	(memcmp((a),(b),sizeof(sm9_fp2_t)) == 0)

static void sm9_fp2_from_hex(sm9_fp2_t r, const char hex[65 * 2]);

static void sm9_fp2_to_hex(const sm9_fp2_t a, char hex[65 * 2]);

static void sm9_fp2_print(const char *prefix, const sm9_fp2_t a);

#define sm9_fp2_set_zero(a)	memset((a), 0, sizeof(sm9_fp2_t))
#define sm9_fp2_set_one(a)	memcpy((a), &SM9_FP2_ONE, sizeof(sm9_fp2_t))

static void sm9_fp2_set_fp(sm9_fp2_t r, const sm9_fp_t a);

#define sm9_fp2_set_u(a)	memcpy((a), &SM9_FP2_U, sizeof(sm9_fp2_t))

static void sm9_fp2_set(sm9_fp2_t r, const sm9_fp_t a0, const sm9_fp_t a1);
static void sm9_fp2_add(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);
static void sm9_fp2_dbl(sm9_fp2_t r, const sm9_fp2_t a);

static void sm9_fp2_tri(sm9_fp2_t r, const sm9_fp2_t a);

static void sm9_fp2_sub(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);

static void sm9_fp2_neg(sm9_fp2_t r, const sm9_fp2_t a);
static void sm9_fp2_mul(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);

static void sm9_fp2_mul_u(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);

static void sm9_fp2_mul_fp(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp_t k);

static void sm9_fp2_sqr(sm9_fp2_t r, const sm9_fp2_t a);

static void sm9_fp2_sqr_u(sm9_fp2_t r, const sm9_fp2_t a);

static void sm9_fp2_inv(sm9_fp2_t r, const sm9_fp2_t a);

static void sm9_fp2_div(sm9_fp2_t r, const sm9_fp2_t a, const sm9_fp2_t b);

static void sm9_fp2_div2(sm9_fp2_t r, const sm9_fp2_t a);

static const sm9_fp4_t SM9_FP4_ZERO = {{{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}, {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
static const sm9_fp4_t SM9_FP4_ONE = {{{1,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}, {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
static const sm9_fp4_t SM9_FP4_U = {{{0,0,0,0,0,0,0,0},{1,0,0,0,0,0,0,0}}, {{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};
static const sm9_fp4_t SM9_FP4_V = {{{0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}, {{1,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0}}};

#define sm9_fp4_init(r)	memcpy((r), &SM9_FP4_ZERO, sizeof(sm9_fp4_t))
#define sm9_fp4_clean(r)	memcpy((r), &SM9_FP4_ZERO, sizeof(sm9_fp4_t))
#define sm9_fp4_set_zero(r)	memcpy((r), &SM9_FP4_ZERO, sizeof(sm9_fp4_t))
#define sm9_fp4_set_one(r)	memcpy((r), &SM9_FP4_ONE, sizeof(sm9_fp4_t))
#define sm9_fp4_is_zero(a)	(memcmp((a), &SM9_FP4_ZERO, sizeof(sm9_fp4_t)) == 0)
#define sm9_fp4_is_one(a)	(memcmp((a), &SM9_FP4_ONE, sizeof(sm9_fp4_t)) == 0)
#define sm9_fp4_equ(a,b)	(memcmp((a), (b), sizeof(sm9_fp4_t)) == 0)
#define sm9_fp4_copy(r,a)	memcpy((r), (a), sizeof(sm9_fp4_t))



static void sm9_fp4_from_hex(sm9_fp4_t r, const char hex[65 * 4]);

static void sm9_fp4_to_hex(const sm9_fp4_t a, char hex[65 * 4]);

static void sm9_fp4_set_fp(sm9_fp4_t r, const sm9_fp_t a);

static void sm9_fp4_set_fp2(sm9_fp4_t r, const sm9_fp2_t a);

static void sm9_fp4_set(sm9_fp4_t r, const sm9_fp2_t a0, const sm9_fp2_t a1);

static void sm9_fp4_set_u(sm9_fp4_t r);

static void sm9_fp4_set_v(sm9_fp4_t r);

static void sm9_fp4_add(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);

static void sm9_fp4_dbl(sm9_fp4_t r, const sm9_fp4_t a);

static void sm9_fp4_sub(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);

static void sm9_fp4_neg(sm9_fp4_t r, const sm9_fp4_t a);

static void sm9_fp4_mul(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);

static void sm9_fp4_mul_fp(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp_t k);

static void sm9_fp4_mul_fp2(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp2_t b0);

static void sm9_fp4_mul_v(sm9_fp4_t r, const sm9_fp4_t a, const sm9_fp4_t b);

static void sm9_fp4_sqr(sm9_fp4_t r, const sm9_fp4_t a);

static void sm9_fp4_sqr_v(sm9_fp4_t r, const sm9_fp4_t a);

static void sm9_fp4_inv(sm9_fp4_t r, const sm9_fp4_t a);


#define sm9_fp12_init(r)	memset((r), 0, sizeof(sm9_fp12_t))
#define sm9_fp12_clean(r)	memset((r), 0, sizeof(sm9_fp12_t))
#define sm9_fp12_set_zero(r)	memset((r), 0, sizeof(sm9_fp12_t))
#define sm9_fp12_copy(r, a)	memcpy((r), (a), sizeof(sm9_fp12_t))

static void sm9_fp12_set_one(sm9_fp12_t r);

static int sm9_fp12_is_one(const sm9_fp12_t a);

static int sm9_fp12_is_zero(const sm9_fp12_t a);

static void sm9_fp12_from_hex(sm9_fp12_t r, const char hex[65 * 12]);

static void sm9_fp12_to_hex(const sm9_fp12_t a, char hex[65 * 12]);

static void sm9_fp12_print(const char *prefix, const sm9_fp12_t a);

static void sm9_fp12_set(sm9_fp12_t r, const sm9_fp4_t a0, const sm9_fp4_t a1, const sm9_fp4_t a2);

static void sm9_fp12_set_fp(sm9_fp12_t r, const sm9_fp_t a);

static void sm9_fp12_set_fp2(sm9_fp12_t r, const sm9_fp2_t a);

static void sm9_fp12_set_fp4(sm9_fp12_t r, const sm9_fp4_t a);

static void sm9_fp12_set_u(sm9_fp12_t r);

static void sm9_fp12_set_v(sm9_fp12_t r);

static void sm9_fp12_set_w(sm9_fp12_t r);

static void sm9_fp12_set_w_sqr(sm9_fp12_t r);

static int sm9_fp12_equ(const sm9_fp12_t a, const sm9_fp12_t b);

static void sm9_fp12_add(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b);

static void sm9_fp12_dbl(sm9_fp12_t r, const sm9_fp12_t a);

static void sm9_fp12_tri(sm9_fp12_t r, const sm9_fp12_t a);

static void sm9_fp12_sub(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b);

static void sm9_fp12_neg(sm9_fp12_t r, const sm9_fp12_t a);
static void sm9_fp12_mul(sm9_fp12_t r, const sm9_fp12_t a, const sm9_fp12_t b);

static void sm9_fp12_sqr(sm9_fp12_t r, const sm9_fp12_t a);

static void sm9_fp12_inv(sm9_fp12_t r, const sm9_fp12_t a);

static void sm9_fp12_pow(sm9_fp12_t r, const sm9_fp12_t a, const sm9_bn_t k);

static void sm9_fp2_conjugate(sm9_fp2_t r, const sm9_fp2_t a);

static void sm9_fp2_frobenius(sm9_fp2_t r, const sm9_fp2_t a);

// beta   = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
// alpha1 = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
// alpha2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
// alpha3 = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
// alpha4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333
// alpha5 = 0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686
static const sm9_fp2_t SM9_BETA = {{0xda24d011, 0xf5b21fd3, 0x06dc5177, 0x9f9d4118, 0xee0baf15, 0xf55acc93, 0xdc0a3f2c, 0x6c648de5}, {0}};
static const sm9_fp_t SM9_ALPHA1 = {0x377b698b, 0xa91d8354, 0x0ddd04ed, 0x47c5c86e, 0x9c086749, 0x843c6cfa, 0xe5720bdb, 0x3f23ea58};
static const sm9_fp_t SM9_ALPHA2 = {0x7be65334, 0xd5fc1196, 0x4f8b78f4, 0x78027235, 0x02a3a6f2, 0xf3000000, 0x0,        0x0       };
static const sm9_fp_t SM9_ALPHA3 = {0xda24d011, 0xf5b21fd3, 0x06dc5177, 0x9f9d4118, 0xee0baf15, 0xf55acc93, 0xdc0a3f2c, 0x6c648de5};
static const sm9_fp_t SM9_ALPHA4 = {0x7be65333, 0xd5fc1196, 0x4f8b78f4, 0x78027235, 0x02a3a6f2, 0xf3000000, 0x0,        0x0       };
static const sm9_fp_t SM9_ALPHA5 = {0xa2a96686, 0x4c949c7f, 0xf8ff4c8a, 0x57d778a9, 0x520347cc, 0x711e5f99, 0xf6983351, 0x2d40a38c};


static void sm9_fp4_frobenius(sm9_fp4_t r, const sm9_fp4_t a);

static void sm9_fp4_conjugate(sm9_fp4_t r, const sm9_fp4_t a);

static void sm9_fp4_frobenius2(sm9_fp4_t r, const sm9_fp4_t a);

static void sm9_fp4_frobenius3(sm9_fp4_t r, const sm9_fp4_t a);

static void sm9_fp12_frobenius(sm9_fp12_t r, const sm9_fp12_t x);

static void sm9_fp12_frobenius2(sm9_fp12_t r, const sm9_fp12_t x);

static void sm9_fp12_frobenius3(sm9_fp12_t r, const sm9_fp12_t x);

static void sm9_fp12_frobenius6(sm9_fp12_t r, const sm9_fp12_t x);


static void sm9_point_init(sm9_point_t *R);

static void sm9_point_from_hex(sm9_point_t *R, const char hex[65 * 2]);

#define sm9_point_copy(R, P)	memcpy((R), (P), sizeof(sm9_point_t))

static int sm9_point_is_at_infinity(const sm9_point_t *P);

static void sm9_point_set_infinity(sm9_point_t *R);
static void sm9_point_get_xy(const sm9_point_t *P, sm9_fp_t x, sm9_fp_t y);

static int sm9_point_equ(const sm9_point_t *P, const sm9_point_t *Q);

static int sm9_point_is_on_curve(const sm9_point_t *P);

static void sm9_point_dbl(sm9_point_t *R, const sm9_point_t *P);

static void sm9_point_add(sm9_point_t *R, const sm9_point_t *P, const sm9_point_t *Q);

static void sm9_point_neg(sm9_point_t *R, const sm9_point_t *P);

static void sm9_point_sub(sm9_point_t *R, const sm9_point_t *P, const sm9_point_t *Q);

static void sm9_point_mul(sm9_point_t *R, const sm9_bn_t k, const sm9_point_t *P);

static void sm9_point_mul_generator(sm9_point_t *R, const sm9_bn_t k);


static void sm9_twist_point_from_hex(sm9_twist_point_t *R, const char hex[65 * 4]);

#define sm9_twist_point_copy(R, P)	memcpy((R), (P), sizeof(sm9_twist_point_t))

static int sm9_twist_point_is_at_infinity(const sm9_twist_point_t *P);

static void sm9_twist_point_set_infinity(sm9_twist_point_t *R);

static void sm9_twist_point_get_xy(const sm9_twist_point_t *P, sm9_fp2_t x, sm9_fp2_t y);


static int sm9_twist_point_equ(const sm9_twist_point_t *P, const sm9_twist_point_t *Q);
static int sm9_twist_point_is_on_curve(const sm9_twist_point_t *P);

static void sm9_twist_point_neg(sm9_twist_point_t *R, const sm9_twist_point_t *P);

static void sm9_twist_point_dbl(sm9_twist_point_t *R, const sm9_twist_point_t *P);

static void sm9_twist_point_add(sm9_twist_point_t *R, const sm9_twist_point_t *P, const sm9_twist_point_t *Q);

static void sm9_twist_point_sub(sm9_twist_point_t *R, const sm9_twist_point_t *P, const sm9_twist_point_t *Q);

static void sm9_twist_point_add_full(sm9_twist_point_t *R, const sm9_twist_point_t *P, const sm9_twist_point_t *Q);
static void sm9_twist_point_mul(sm9_twist_point_t *R, const sm9_bn_t k, const sm9_twist_point_t *P);

static void sm9_twist_point_mul_G(sm9_twist_point_t *R, const sm9_bn_t k);

static void sm9_eval_g_tangent(sm9_fp12_t num, sm9_fp12_t den, const sm9_twist_point_t *P, const sm9_point_t *Q);

static void sm9_eval_g_line(sm9_fp12_t num, sm9_fp12_t den, const sm9_twist_point_t *T, const sm9_twist_point_t *P, const sm9_point_t *Q);

static void sm9_twist_point_pi1(sm9_twist_point_t *R, const sm9_twist_point_t *P);
static void sm9_twist_point_pi2(sm9_twist_point_t *R, const sm9_twist_point_t *P);
static void sm9_twist_point_neg_pi2(sm9_twist_point_t *R, const sm9_twist_point_t *P);


static void sm9_final_exponent_hard_part(sm9_fp12_t r, const sm9_fp12_t f);
static void sm9_final_exponent(sm9_fp12_t r, const sm9_fp12_t f);
static void sm9_pairing(sm9_fp12_t r, const sm9_twist_point_t *Q, const sm9_point_t *P);

void sm9_pairing_test();


#  ifdef  __cplusplus
}
#  endif
# endif
