#include <gmssl/pem.h>
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <string.h>
#include <stdio.h>

static uint8_t str[] = "-----BEGIN CERTIFICATE-----\n\
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


int main(int argc, char **argv) {
    int ret = 0;
    uint8_t buf[1024];
    const uint8_t *cp = buf;
    size_t len = 0;

    X509_CERTIFICATE a;
    memset(buf,0, 1024);
    ret = pem_str_read(str, strlen(str), "CERTIFICATE", buf, &len);
    if (ret != 0){
        error_print();
        return -1;
    }
//    print_der(buf, len);
    ret = x509_certificate_from_der(&a, &cp, &len);
    if (ret != 1){
        error_print();
        return -1;
    }
    x509_certificate_print(stderr, &a, 0, 0);
}