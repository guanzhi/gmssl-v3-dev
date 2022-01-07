#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gmssl/error.h>
#include <gmssl/tlcp_socket.h>
#include <gmssl/rand.h>

static uint8_t cacert_str[] = "-----BEGIN CERTIFICATE-----\n\
MIIB3jCCAYOgAwIBAgIIAs4MAPwpIBcwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC\n\
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm\n\
tYvor5VDQTAeFw0yMTEyMjMwODQ4MzNaFw0zMTEyMjMwODQ4MzNaMEIxCzAJBgNV\n\
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njERMA8GA1UE\n\
CgwI5rWL6K+VQ0EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARKs6B5ZBy753Os\n\
ZSeIfv8zScbiiXkLjB+Plw+YWvoesRkqYGe/Mqjr8rrmThq6iEWubYK6ZiQQV54k\n\
Klcva3Hto2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV\n\
HQ4EFgQUNpPjFOdFCfrV7+ovEi3ToZY8wqQwHwYDVR0jBBgwFoAUNpPjFOdFCfrV\n\
7+ovEi3ToZY8wqQwCgYIKoEcz1UBg3UDSQAwRgIhALDhtLKVziUhXbTedDovRANS\n\
Cdu6CJ0MAw7Wbl3vAWGOAiEAzCXLcF32DM5Aze9MqpUfQfYPaRTLYkNwSXlw/LUY\n\
E6E=\n\
-----END CERTIFICATE-----";

static uint8_t sigcert_str[] = "-----BEGIN CERTIFICATE-----\n\
MIICHTCCAcSgAwIBAgIIAs4MDJsDUfcwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC\n\
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm\n\
tYvor5VDQTAeFw0yMTEyMjgwNzU4MDdaFw0yMjEyMjgwNzU4MDdaMHExCzAJBgNV\n\
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEPMA0GA1UE\n\
CgwG5rWL6K+VMRUwEwYDVQQLDAzmtYvor5Xpg6jpl6gxGDAWBgNVBAMMD+a1i+iv\n\
leacjeWKoeWZqDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAlMWC6hI1v9MRdf\n\
BjXDdfD7v1bdgWDclZCUlXHYVmbNa5PzHpoh6JyK/TC7C5ph+hxQLc4fCREqqF8K\n\
Q8Ct0fajdTBzMA4GA1UdDwEB/wQEAwIGwDATBgNVHSUEDDAKBggrBgEFBQcDATAM\n\
BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRVnXu8fDpWLji6+B4agt+UjtenVTAfBgNV\n\
HSMEGDAWgBQ2k+MU50UJ+tXv6i8SLdOhljzCpDAKBggqgRzPVQGDdQNHADBEAiAC\n\
cFef0JAGpBPlrUZLf56fLEGQx5ifSqBZJ9qTANAAfwIgM/nrEqeO7Scjzn9dFFRk\n\
Yf4zl0ev+DBFoMBySPj4SIk=\n\
-----END CERTIFICATE-----";

static uint8_t enccert_str[] = "-----BEGIN CERTIFICATE-----\n\
MIICHTCCAcSgAwIBAgIIAs4MDJsDWYcwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC\n\
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm\n\
tYvor5VDQTAeFw0yMTEyMjgwNzU4MDdaFw0yMjEyMjgwNzU4MDdaMHExCzAJBgNV\n\
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEPMA0GA1UE\n\
CgwG5rWL6K+VMRUwEwYDVQQLDAzmtYvor5Xpg6jpl6gxGDAWBgNVBAMMD+a1i+iv\n\
leacjeWKoeWZqDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAjaZJ4zeudYfvQ+\n\
d5PscKx116VQBzLtYzFcQKPeI8DXis2rDdT7BrGa8ixdF1iatD+TyT5kmMz4Jf1G\n\
6QNNYeKjdTBzMA4GA1UdDwEB/wQEAwIDODATBgNVHSUEDDAKBggrBgEFBQcDATAM\n\
BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQChe9/DMXc8kGC84j8FW4Nkb41uTAfBgNV\n\
HSMEGDAWgBQ2k+MU50UJ+tXv6i8SLdOhljzCpDAKBggqgRzPVQGDdQNHADBEAiAh\n\
MIuWxdAQ71kwT95+0fvm9VuuCOpusHgbDWJanyZBnAIgTIXAkehTXPLYXjYJ/uVE\n\
4DdAQJFVrWNugK3eiDgECMc=\n\
-----END CERTIFICATE-----";

static uint8_t sigkey_str[] = "-----BEGIN EC PRIVATE KEY-----\n\
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgmfgsjOI+jhOcwu7f\n\
Cy6PYSYBmjAzTijLaJicJorUEsmgCgYIKoEcz1UBgi2hRANCAAQJTFguoSNb/TEX\n\
XwY1w3Xw+79W3YFg3JWQlJVx2FZmzWuT8x6aIeiciv0wuwuaYfocUC3OHwkRKqhf\n\
CkPArdH2\n\
-----END EC PRIVATE KEY-----";

static uint8_t enckey_str[] = "-----BEGIN EC PRIVATE KEY-----\n\
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgBdQfH874+gihD5WM\n\
q2UGdLWzXoVEANZ+nShGd7aW8OegCgYIKoEcz1UBgi2hRANCAAQI2mSeM3rnWH70\n\
PneT7HCsddelUAcy7WMxXECj3iPA14rNqw3U+waxmvIsXRdYmrQ/k8k+ZJjM+CX9\n\
RukDTWHi\n\
-----END EC PRIVATE KEY-----";

static X509_CERTIFICATE cacert;
static X509_CERTIFICATE sigcert;
static X509_CERTIFICATE enccert;
static SM2_KEY          sigkey;
static SM2_KEY          enckey;

static int load_cert_keys();

static void handle_http(TLCP_SOCKET_CONNECT *conn);

static void handle_read_write(TLCP_SOCKET_CONNECT *conn);

static void client_conn_test();

int main(void) {
//    TLCP_SOCKET_CTX     ctx;
//    TLCP_SOCKET_KEY     socket_sigkey;
//    TLCP_SOCKET_KEY     socket_enckey;
//    TLCP_SOCKET_CONNECT conn;

    // 加载证书和相关密钥
    if (load_cert_keys() != 1) {
        return -1;
    }
    client_conn_test();

//    // 创建SOCKET使用的密钥对
//    if (TLCP_SOCKET_GMSSL_Key(&socket_sigkey, &sigcert, &sigkey) != 1) {
//        return -1;
//    }
//    if (TLCP_SOCKET_GMSSL_Key(&socket_enckey, &enccert, &enckey) != 1) {
//        return -1;
//    }
//    // 初始化上下文
//    ctx.rand           = rand_bytes;
//    ctx.server_sig_key = &socket_sigkey;
//    ctx.server_enc_key = &socket_enckey;
//    // 打开端口监听TLCP连接
//    if (TLCP_SOCKET_Listen(&ctx, 30443) != 1) {
//        return -1;
//    }
//    for (;;) {
//        if (TLCP_SOCKET_Accept(&ctx, &conn) != 1) {
//            error_print();
//            break;
//        }
////        handle_http(&conn);
//        handle_read_write(&conn);
//        TLCP_SOCKET_Connect_Close(&conn);
//    }
//    // 关闭连接
//    TLCP_SOCKET_Close(&ctx);
}

// 测试数据的读写
static void handle_read_write(TLCP_SOCKET_CONNECT *conn) {
    size_t  n                        = 0;
    uint8_t buf[TLS_MAX_RECORD_SIZE] = {0};
    uint8_t resp[1024 * 1024]        = {0};
    size_t  i                        = 0;

    n      = sizeof(buf);
    if ((n = TLCP_SOCKET_Read(conn, buf, n)) < 0) {
        error_print();
        return;
    }
    printf("%s\n", buf);
    n      = TLCP_SOCKET_DEFAULT_FRAME_SIZE * 5 + 1;
    for (i = 0; i < n; ++i) {
        resp[i] = 'A';
    }
    if ((n = TLCP_SOCKET_Write(conn, resp, n)) < 0) {
        error_print();
        return;
    }
}

// 测试HTTP服务器
static void handle_http(TLCP_SOCKET_CONNECT *conn) {
    size_t  n                        = 0;
    uint8_t buf[TLS_MAX_RECORD_SIZE] = {0};
    uint8_t resp[]                   = "HTTP/1.1 200 OK\r\n\
Content-Length: 6\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hello!";
    n      = sizeof(buf);
    if ((n = TLCP_SOCKET_Read(conn, buf, n)) < 0) {
        error_print();
        return;
    }
    printf("%s\n", buf);
    if ((n = TLCP_SOCKET_Write(conn, resp, sizeof(resp))) < 0) {
        error_print();
        return;
    }
}

static int load_cert_keys() {
    if (x509_certificate_from_bytes(&cacert, cacert_str, strlen(cacert_str)) != 1) {
        error_print();
        return -1;
    }
    if (x509_certificate_from_bytes(&sigcert, sigcert_str, strlen(sigcert_str)) != 1) {
        error_print();
        return -1;
    }
    if (x509_certificate_from_bytes(&enccert, enccert_str, strlen(enccert_str)) != 1) {
        error_print();
        return -1;
    }
    if (sm2_private_key_from_str_pem(&sigkey, sigkey_str, strlen(sigkey_str)) != 1) {
        error_print();
        return -1;
    }
    if (sm2_private_key_from_str_pem(&enckey, enckey_str, strlen(enckey_str)) != 1) {
        error_print();
        return -1;
    }
    return 1;
}

#define BUFFER_SIZE 4096

/**
 * 客户端连接读写测试
 */
static void client_conn_test() {
    TLCP_SOCKET_CTX     ctx = {0};
    TLCP_SOCKET_CONNECT conn;
    int                 ret = 1;

    ctx.root_certs    = &cacert;
    ctx.root_cert_len = 1;
    uint8_t send[BUFFER_SIZE] = {0};
    uint8_t recv[BUFFER_SIZE] = {0};

    size_t  n                 = BUFFER_SIZE;
    size_t  rd                = 0;
    uint8_t *p                = 0;

    errno                   = 0;
    // 拨号连接服务端
    ret = TLCP_SOCKET_Dial(&ctx, &conn, "127.0.0.1", 7777);
    if (ret != 1) {
        error_print();
        return;
    }
    for (;;) {
        n = BUFFER_SIZE;
        if (rand_bytes(send, n) != 1) {
            perror("rand_bytes() ERROR");
            break;
        }

        if ((n = TLCP_SOCKET_Write(&conn, send, n)) < 0) {
            perror("TLCP_SOCKET_Write() ERROR");
            break;
        }
        // print_bytes(send, n);

        // 不断读取数据直到满足长度
        rd     = 0;
        p      = recv;
        do {
            if ((n = TLCP_SOCKET_Read(&conn, p, BUFFER_SIZE - rd)) < 0) {
                perror("TLCP_SOCKET_Read() ERROR");
                break;
            }
            rd += n;
            p      = recv + rd;
        } while (rd < BUFFER_SIZE);

        // print_bytes(recv, n);
        // 比较数据读写数据是否一致
        if (memcmp(send, recv, BUFFER_SIZE) != 0) {
            perror("Write Read Different!");
            break;
        }
    }
    TLCP_SOCKET_Connect_Close(&conn);

}