/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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
#include <gmssl/x509.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/base64.h>



static int test_x509_validity(void)
{
	int err = 0;
	X509_VALIDITY validity;
	uint8_t buf[64] = {0};
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;
	size_t i;

	printf("%s\n", __FUNCTION__);
	memset(&validity, 0, sizeof(X509_VALIDITY));

	x509_validity_set_days(&validity, time(NULL), 365 * 10);
	x509_validity_to_der(&validity, &p, &len);
	print_der(buf, len);
	printf("\n");

	memset(&validity, 0, sizeof(X509_VALIDITY));
	x509_validity_from_der(&validity, &cp, &len);
	x509_validity_print(stdout, &validity, 0, 0);

	printf("\n");
	return err;
}

static int test_x509_name(void)
{
	int err = 0;
	X509_NAME name;
	uint8_t buf[1024];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;

	printf("%s\n", __FUNCTION__);

	memset(&name, 0, sizeof(X509_NAME));
	x509_name_add_rdn(&name, OID_at_countryName, ASN1_TAG_PrintableString, "CN");
	x509_name_add_rdn(&name, OID_at_stateOrProvinceName, ASN1_TAG_PrintableString, "Beijing");
	x509_name_add_rdn(&name, OID_at_organizationName, ASN1_TAG_PrintableString, "PKU");
	x509_name_add_rdn(&name, OID_at_organizationalUnitName, ASN1_TAG_PrintableString, "CS");
	x509_name_add_rdn(&name, OID_at_commonName, ASN1_TAG_PrintableString, "infosec");

	if (x509_name_to_der(&name, &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	print_der(buf, len);
	printf("\n");

	if (x509_name_from_der(&name, &cp, &len) != 1
		|| len > 0) {
		error_print();
		err++;
		goto end;
	}
	x509_name_print(stdout, &name, 0, 0);

end:
	printf("\n");
	return err;
}

static int test_x509_signature_algor(int oid)
{
	int err = 0;
	int tests[] = {OID_sm2sign_with_sm3, OID_rsasign_with_sm3};
	int val;
	uint32_t nodes[32];
	size_t nodes_count;
	uint8_t buf[128];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;
	size_t i;

	printf("%s\n", __FUNCTION__);
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("%s\n", asn1_object_identifier_name(tests[i]));
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_signature_algor_to_der(tests[i], &p, &len) != 1) {
			error_print();
			err++;
			goto end;
		}
		print_der(buf, len);
		printf("\n");
	}
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		if (x509_signature_algor_from_der(&val, nodes, &nodes_count, &cp, &len) != 1) {
			error_print();
			err++;
			goto end;
		}
		if (val != tests[i]) {
			error_print();
			err++;
			goto end;
		}
		printf("%s\n", asn1_object_identifier_name(tests[i]));
	}

end:
	printf("\n");
	return err;
}

static int test_x509_public_key_info(void)
{
	int err = 0;
	SM2_KEY key;
	X509_PUBLIC_KEY_INFO pkey_info;
	uint8_t buf[256];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;

	printf("%s\n", __FUNCTION__);

	sm2_keygen(&key);
	x509_public_key_info_set_sm2(&pkey_info, &key);

	if (x509_public_key_info_to_der(&pkey_info, &p, &len) != 1) {
		error_print();
		return -1;
	}
	print_der(buf, len);
	printf("\n");

	if (x509_public_key_info_from_der(&pkey_info, &cp, &len) != 1
		|| len > 0) {
		error_print();
		return -1;
	}

	x509_public_key_info_print(stdout, &pkey_info, 0, 0);

	printf("\n");
	return err;
}

static int test_x509_certificate(void)
{
	int err = 0;
	X509_CERTIFICATE _cert, *cert = &_cert;
	int rv;
	int version = X509_version_v3;
	uint8_t sn[12];
	X509_NAME issuer;
	X509_NAME subject;
	time_t not_before;

	SM2_KEY key;

	uint8_t buf[2048] = {0};
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	printf("%s\n", __FUNCTION__);

	memset(cert, 0, sizeof(X509_CERTIFICATE));

	rand_bytes(sn, sizeof(sn));

	memset(&issuer, 0, sizeof(X509_NAME));
	// add_rdn 应该用一个ex来支持长度
	x509_name_add_rdn(&issuer, OID_at_countryName, ASN1_TAG_PrintableString, "CN");
	x509_name_add_rdn(&issuer, OID_at_stateOrProvinceName, ASN1_TAG_PrintableString, "Beijing");
	x509_name_add_rdn(&issuer, OID_at_organizationName, ASN1_TAG_PrintableString, "PKU");
	x509_name_add_rdn(&issuer, OID_at_organizationalUnitName, ASN1_TAG_PrintableString, "CS");
	x509_name_add_rdn(&issuer, OID_at_commonName, ASN1_TAG_PrintableString, "CA");

	memset(&subject, 0, sizeof(X509_NAME));
	x509_name_add_rdn(&subject, OID_at_countryName, ASN1_TAG_PrintableString, "CN");
	x509_name_add_rdn(&subject, OID_at_stateOrProvinceName, ASN1_TAG_PrintableString, "Beijing");
	x509_name_add_rdn(&subject, OID_at_organizationName, ASN1_TAG_PrintableString, "PKU");
	x509_name_add_rdn(&subject, OID_at_organizationalUnitName, ASN1_TAG_PrintableString, "CS");
	x509_name_add_rdn(&subject, OID_at_commonName, ASN1_TAG_PrintableString, "infosec");

	time(&not_before);

	rv = x509_certificate_set_version(cert, version);
	rv = x509_certificate_set_serial_number(cert, sn, sizeof(sn));
	rv = x509_certificate_set_signature_algor(cert, OID_sm2sign_with_sm3); // 这个不是应该在设置公钥的时候一起设置吗？
	rv = x509_certificate_set_issuer(cert, &issuer);
	rv = x509_certificate_set_subject(cert, &subject);
	rv = x509_certificate_set_validity(cert, not_before, 365);

	sm2_keygen(&key);
	rv = x509_certificate_set_subject_public_key_info_sm2(cert, &key);


	rv = x509_certificate_generate_subject_key_identifier(cert, 1);


	rv = x509_certificate_sign_sm2(cert, &key);

	rv = x509_certificate_to_der(cert, &p, &len);
	print_der(buf, len);
	printf("\n");

	memset(cert, 0, sizeof(X509_CERTIFICATE));
	x509_certificate_from_der(cert, &cp, &len);

	x509_certificate_print(stdout, cert, 0, 0);


	return 0;
}

static int test_x509_cert_request(void)
{
	int err = 0;
	X509_CERT_REQUEST req;
	X509_NAME subject;
	SM2_KEY keypair;
	uint8_t buf[256];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len = 0;

	printf("%s : \n", __func__);

	memset(&subject, 0, sizeof(X509_NAME));
	x509_name_add_rdn(&subject, OID_at_countryName, ASN1_TAG_PrintableString, "CN");
	x509_name_add_rdn(&subject, OID_at_stateOrProvinceName, ASN1_TAG_PrintableString, "Beijing");
	x509_name_add_rdn(&subject, OID_at_organizationName, ASN1_TAG_PrintableString, "PKU");
	x509_name_add_rdn(&subject, OID_at_organizationalUnitName, ASN1_TAG_PrintableString, "CS");
	x509_name_add_rdn(&subject, OID_at_commonName, ASN1_TAG_PrintableString, "infosec");

	sm2_keygen(&keypair);

	if (x509_cert_request_set_sm2(&req, &subject, &keypair) != 1
		|| x509_cert_request_sign_sm2(&req, &keypair) != 1
		|| x509_cert_request_to_der(&req, &p, &len) != 1) {
		error_print();
		err++;
		goto end;
	}
	print_der(buf, len);
	printf("\n");

	memset(&req, 0, sizeof(req));
	if (x509_cert_request_from_der(&req, &cp, &len) != 1) {
		error_print();
		err++;
		goto end;
	}

	x509_cert_request_print(stdout, &req, 0, 0);

end:
	return err;
}

int test_x509_cert_parse() {
    uint8_t pem_str[] = "-----BEGIN CERTIFICATE-----\n\
MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG\n\
EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw\n\
MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO\n\
UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE\n\
MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT\n\
V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti\n\
W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ\n\
MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b\n\
53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI\n\
pDoiVhsLwg==\n\
-----END CERTIFICATE-----";
    uint8_t base64_str[] = "MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQGEwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQwMzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVOUkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEMPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRTV7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5YtiW/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZMxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xIpDoiVhsLwg==";
    uint8_t hex_str[] = "308202A63082024AA00302010202101F35D919056CE68D022E51F38A7A0837300C06082A811CCF550183750500302E310B300906035504061302434E310E300C060355040A0C054E52434143310F300D06035504030C06524F4F544341301E170D3133313232313032343634315A170D3333313231363032343634315A3052310B300906035504061302434E312F302D060355040A0C265A68656A69616E67204469676974616C20436572746966696361746520417574686F726974793112301006035504030C095A4A4341204F4341313059301306072A8648CE3D020106082A811CCF5501822D03420004E9E3CB66A2421721109EEB1F4EE62695562365BF5623C2DD586C5F43A57EB7B92BAEAB6062A19872F925B035D5C862BA11E330150D0A0F312CEB149D52984C9FA38201223082011E301F0603551D230418301680144C32B197D9331BC4A605C1C6E58B625BF0977658300F0603551D130101FF040530030101FF3081BA0603551D1F0481B23081AF3041A03FA03DA43B3039310B300906035504061302434E310E300C060355040A0C054E52434143310C300A060355040B0C0341524C310C300A06035504030C0361726C302AA028A0268624687474703A2F2F7777772E726F6F7463612E676F762E636E2F61726C2F61726C2E63726C303EA03CA03A86386C6461703A2F2F6C6461702E726F6F7463612E676F762E636E3A3338392F434E3D61726C2C4F553D41524C2C4F3D4E524341432C433D434E300E0603551D0F0101FF040403020106301D0603551D0E04160414A7D3B12490201D3DB454EE4B37285291AE2C6A22300C06082A811CCF550183750500034800304502210092EEB5F2FB74B11B33B10FD100B037983458C2C123F306E477BD37AA1111A61902201B5B2A50077E1B846352A9442CF9140862972DE32379508B9F8AC6FD04759021";
    uint8_t der[1024];
    const uint8_t *cp = der;
    size_t der_len = 0;
    int len;
    X509_CERTIFICATE  a;

    if (base64_str_decode(base64_str, strlen(base64_str), der, &len) == -1){
        error_puts("无法解码BASE64");
        return -1;
    }
    der_len = len;

    printf("Base64 解码成功, DER len = %d\n", len);
    // CASE 1 测试DER编码
    if (x509_certificate_from_bytes(&a, der, der_len) == -1){
        error_puts("CASE1 DER解析失败");
        return -1;
    }
    printf("CASE1 DER解析成功\n");
    memset(der, 0, 1024);
    memset(&a,0,sizeof(a));

    // CASE 2 测试PEM解码
    if (x509_certificate_from_bytes(&a, pem_str, strlen(pem_str)) == -1){
        error_puts("CASE2 PEM解析失败");
        return -1;
    }
    printf("CASE2 PEM解析成功\n");
    memset(der, 0, 1024);
    memset(&a,0,sizeof(a));

    // CASE 3 BASE64解码
    if (x509_certificate_from_bytes(&a, base64_str, strlen(base64_str)) == -1){
        error_puts("CASE3 BASE64解析失败");
        return -1;
    }
    printf("CASE3 BASE64解析成功\n");
    memset(der, 0, 1024);
    memset(&a,0,sizeof(a));

    // CASE 4 HEX解码
    if (x509_certificate_from_bytes(&a, hex_str, strlen(hex_str)) == -1){
        error_puts("CASE4 HEX解析失败");
        return -1;
    }
    printf("CASE4 HEX解析成功\n");
    memset(der, 0, 1024);
    memset(&a,0,sizeof(a));

    return 0;
}


int main(void)
{
	int err = 0;
	// err += test_x509_validity();
	 err += test_x509_signature_algor(OID_sm2sign_with_sm3);
	 err += test_x509_signature_algor(OID_rsasign_with_sm3);
	 err += test_x509_name();
	 err += test_x509_public_key_info();
	 err += test_x509_certificate();
	// err += test_x509_cert_request();
    err += test_x509_cert_parse();
    // test_x509_extensions();

	return 1;
}
