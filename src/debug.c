﻿/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
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
#include <stdint.h>
#include <gmssl/error.h>

void print_der(const uint8_t *in, size_t inlen)
{
	size_t i;
	for (i = 0; i < inlen; i++) {
		printf("%02x ", in[i]);
	}
}

void print_bytes(const uint8_t *data, size_t datalen)
{
	size_t i;
	for (i = 0; i < datalen; i++) {
		printf("%02X ", data[i]);
		if ((i + 1) % 32 == 0)
			printf("\n");
	}
	printf("\n");
}

void print_hex_str(const uint8_t *data, size_t datalen)
{
    size_t i;
    for (i = 0; i < datalen; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}


void print_nodes(const uint32_t *in, size_t inlen)
{
	size_t i;
	printf("%u", in[0]);
	for (i = 1; i < inlen; i++) {
		printf(".%u", in[i]);
	}
}



int format_print(FILE *fp, int format, int indent, const char *str, ...)
{
	va_list args;
	int i;
	for (i = 0; i < indent; i++) {
		fprintf(fp, " ");
	}
	va_start(args, str);
	vfprintf(fp, str, args);
	va_end(args);
	return 1;
}

int format_bytes(FILE *fp, int format, int indent, const char *str, const uint8_t *data, size_t datalen)
{
	int i;

	if (datalen > 4096) {
		error_print();
		return -1;
	}

	for (i = 0; i < indent; i++) {
		fprintf(fp, " ");
	}
	fprintf(fp, "%s", str);
	if (!datalen) {
		fprintf(fp, "(null)\n");
		return 1;
	}
	for (i = 0; i < datalen; i++) {
		fprintf(fp, "%02X", data[i]);
	}
	fprintf(fp, "\n");
	return 1;
}


int tls_trace(int format, int indent, const char *str, ...)
{
	FILE *fp = stderr;
	va_list args;
	int i;
	for (i = 0; i < indent; i++) {
		fprintf(fp, " ");
	}
	va_start(args, str);
	vfprintf(fp, str, args);
	va_end(args);
	fprintf(fp, "\n");
	return 1;
}

