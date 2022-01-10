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

static uint8_t client_cert_str[] = "-----BEGIN CERTIFICATE-----\n\
MIICADCCAaWgAwIBAgIIAs5czZZPpv4wCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC\n\
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm\n\
tYvor5VDQTAeFw0yMjAxMDcwNTM4MTBaFw0yMzAxMDcwNTM4MTBaMGcxCzAJBgNV\n\
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEPMA0GA1UE\n\
CgwG5rWL6K+VMQ8wDQYDVQQLDAbmtYvor5UxFDASBgNVBAMMC+WuouaIt+errzAx\n\
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEfjd+8UWsZh/mOtbOV7vtCwJCqSda\n\
abwljsV6mZH7Ugbp7Zx3nTRGE0L2WXGQaOe/78Ph2kErp/WGrJUNRVUbwaNgMF4w\n\
DgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBiDmyfgvxB7\n\
TeH0OZez3Cod88iaMB8GA1UdIwQYMBaAFDaT4xTnRQn61e/qLxIt06GWPMKkMAoG\n\
CCqBHM9VAYN1A0kAMEYCIQDxELAl+/+puw6/qp9D8ZzwtqXw9W3YKOGS1zRVzJJF\n\
VQIhAOMUyOxCdqvM0xwh9QyfPunnzOzKa4HP3RrFDxDqXYC/\n\
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

static uint8_t client_key_str[] = "-----BEGIN PRIVATE KEY-----\n\
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgcuCN3FyCvaM+XZ9L\n\
xBdBYxtPPBT6Zcb22c5Ho5EiD9agCgYIKoEcz1UBgi2hRANCAAR+N37xRaxmH+Y6\n\
1s5Xu+0LAkKpJ1ppvCWOxXqZkftSBuntnHedNEYTQvZZcZBo57/vw+HaQSun9Yas\n\
lQ1FVRvB\n\
-----END PRIVATE KEY-----";


static X509_CERTIFICATE cacert;
static X509_CERTIFICATE sigcert;
static X509_CERTIFICATE enccert;
static X509_CERTIFICATE client_cert;
static SM2_KEY          sigkey;
static SM2_KEY          enckey;
static SM2_KEY          client_key;

/**
 * 加载测试用使用的证书和密钥对
 */
static int load_cert_keys();

/**
 * TLCP服务器 HTTP测试
 */
static void handle_http(TLCP_SOCKET_CONNECT *conn);

/**
 * TLCP服务器 回音测试
 */
static void handle_echo(TLCP_SOCKET_CONNECT *conn);

/**
 * TLCP客户端 连接读写回音测试
 */
static void client_conn_test();

/**
 * TLCP客户端 双向身份认证测试
 */
static void client_auth_test();

/**
 * 运行TLCP服务端
 */
static void server_test();

int main(void) {
    // 加载证书和相关密钥
    if (load_cert_keys() != 1) {
        error_puts("cert and key load fail.");
        return 1;
    }
//    server_test();
//    client_conn_test();
    client_auth_test();

    return 1;
}

static void server_test() {
    TLCP_SOCKET_CTX     ctx           = {0};
    TLCP_SOCKET_KEY     socket_sigkey = {0};
    TLCP_SOCKET_KEY     socket_enckey = {0};
    TLCP_SOCKET_CONNECT conn          = {0};

    // 创建SOCKET使用的密钥对
    if (TLCP_SOCKET_GMSSL_Key(&socket_sigkey, &sigcert, &sigkey) != 1) {
        error_puts("sig key create fail.");
        return;
    }
    if (TLCP_SOCKET_GMSSL_Key(&socket_enckey, &enccert, &enckey) != 1) {
        error_puts("enc key create fail.");
        return;
    }
    // 初始化上下文
    ctx.rand           = rand_bytes;
    ctx.server_sig_key = &socket_sigkey;
    ctx.server_enc_key = &socket_enckey;
    // 打开端口监听TLCP连接
    if (TLCP_SOCKET_Listen(&ctx, 30443) != 1) {
        perror("TLCP server listen fail");
        return;
    }
    for (;;) {
        if (TLCP_SOCKET_Accept(&ctx, &conn) != 1) {
            perror("TLCP server Accept fail");
            return;
        }
//        handle_http(&conn);
        handle_echo(&conn);
        TLCP_SOCKET_Connect_Close(&conn);
    }
    // 关闭连接
    TLCP_SOCKET_Close(&ctx);
}


static void handle_echo(TLCP_SOCKET_CONNECT *conn) {
    size_t  n                        = 0;
    uint8_t buf[TLS_MAX_RECORD_SIZE] = {0};

    n = sizeof(buf);
    for (;;) {
        if ((n = TLCP_SOCKET_Read(conn, buf, n)) < 0) {
            error_print();
            return;
        }
        if ((n = TLCP_SOCKET_Write(conn, buf, n)) < 0) {
            error_print();
            return;
        }
    }
}

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
    if (x509_certificate_from_bytes(&client_cert, client_cert_str, strlen(client_cert_str)) != 1) {
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
    if (sm2_private_key_from_str_pem(&client_key, client_key_str, strlen(client_key_str)) != 1) {
        error_print();
        return -1;
    }
    return 1;
}

#define BUFFER_SIZE 4096


static void client_conn_test() {
    TLCP_SOCKET_CTX     ctx               = {0};
    TLCP_SOCKET_CONNECT conn              = {0};
    int                 ret               = 1;
    uint8_t             send[BUFFER_SIZE] = {0};
    uint8_t             recv[BUFFER_SIZE] = {0};
    size_t              n                 = BUFFER_SIZE;
    size_t              rd                = 0;
    uint8_t             *p                = 0;

    ctx.root_certs    = &cacert;
    ctx.root_cert_len = 1;
    errno                                 = 0;

    // 拨号连接服务端
    ret = TLCP_SOCKET_Dial(&ctx, &conn, "127.0.0.1", 30443);
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
        rd = 0;
        p  = recv;
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
        break;
    }
    TLCP_SOCKET_Connect_Close(&conn);

}

static void client_auth_test() {
    TLCP_SOCKET_CTX     ctx      = {0};
    TLCP_SOCKET_CONNECT conn     = {0};
    TLCP_SOCKET_KEY     key      = {0};
    int                 ret      = 1;
    uint8_t             buff[16] = {0};
    ssize_t             n        = 16;
    size_t              i        = 0;
    errno                        = 0;


    if (TLCP_SOCKET_GMSSL_Key(&key, &client_cert, &client_key) == -1) {
        perror("TLCP_SOCKET_GMSSL_Key() ERROR");
        return;
    }
    ctx.root_certs     = &cacert;
    ctx.root_cert_len  = 1;
    ctx.client_sig_key = &key;

    for (i = 0; i < n; ++i) {
        buff[i] = i;
    }
    // 拨号连接服务端
    ret = TLCP_SOCKET_Dial(&ctx, &conn, "127.0.0.1", 30443);
    if (ret != 1) {
        error_print();
        return;
    }

    if ((n = TLCP_SOCKET_Write(&conn, buff, n)) < 0) {
        perror("TLCP_SOCKET_Write() ERROR");
        return;
    }
    if ((n = TLCP_SOCKET_Read(&conn, buff, n)) < 0) {
        perror("TLCP_SOCKET_Read() ERROR");
        return;
    }
    print_bytes(buff, n);
    TLCP_SOCKET_Connect_Close(&conn);
}