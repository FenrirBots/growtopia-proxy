#include "http.h"

int base64_encode(struct http_blob * const in, struct http_blob * const out) {
    if (in == NULL ||
        out == NULL) {
        return 0;
    }
}

/* use CryptStringToBinary until we have a working base64 decode function */
int base64_decode(struct http_blob * const in, struct http_blob * const out) {
    char charset[64] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
        '+', '/'
    };

    if (in == NULL ||
        out == NULL) {
        return 0;
    }

    CryptBinaryToString(in->data, in->length, CRYPT_STRING_BASE64HEADER, &out->data, &out->length, 0, 0);
}

/* this is literally just a call to CryptBinaryToString until i get working base64 decoder written */
int http_certificate_pem_decode(struct http_blob * const in, struct http_blob * const out) {
    struct http_blob blob;
    if (in == NULL ||
        out == NULL) {
        return 0;
    }

    if (base64_decode(in, &blob) == 0) {
        return 0;
    }
}

int http_certificate_der_manual_map(struct http_blob * const in, struct http_blob * const out) {
    if (in == NULL ||
        out == NULL) {
        return 0;
    }
}

int http_certificate_der_load() {

}

int http_certificate_initialize() {
    http_certificate_pem_decode();
    http_certificate_der_manual_map();
    http_certificate_der_load();
}