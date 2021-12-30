#include <stdlib.h>
#include <string.h>
#include <gmssl/error.h>
#include <gmssl/tlcp_socket.h>

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

static int load();

int main(void) {
    if (load() != 1) {
        return -1;
    }

}

static int load() {
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
