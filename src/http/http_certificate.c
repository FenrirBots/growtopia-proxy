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

    CryptBinaryToString(in->data, in->length, CRYPT_STRING_BASE64HEADER, &out->data, &out->length);
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

/* Try and get the proxy to work without this, this is a painful idea to even think about */
int http_certificate_der_manual_map(struct http_blob * const in, struct http_blob * const out) {
    if (in == NULL ||
        out == NULL) {
        return 0;
    }
}

int http_certificate_der_load() {

}

int http_certificate_initialize(struct http_instance * const inst, struct http_certificate * const cred) {
    HCERTSTORE store;
    SCHANNEL_CRED auth;
    SECURITY_STATUS status;

    inst->credentials = malloc(sizeof(HTTP_CERTIFICATE));
    if (inst->credentials == NULL) {
        DEBUG_LOG("failed to allocate memory");
        return 0;
    }
    
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, NULL, CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE, cred->location);
    printf("%s\n", cred->location);
    if (store == NULL) {
        DEBUG_LOG("could not open the store");
        return 0;
    }
    
    /* The only method i could get working so far was to search for the issuer of the self-signed certificate */
    // inst->credentials->context = CertEnumCertificatesInStore(store, 0);
    inst->credentials->context = CertFindCertificateInStore(store, 0, 0, CERT_FIND_ANY, 0, 0);
    if (inst->credentials->context == NULL) {
        DEBUG_LOG("could not find the certificate in the store");
        printf("0x%x\n", GetLastError());
        CRYPT_E_NOT_FOUND;
        CertCloseStore(store, 0);
        return 0;
    }
    
    memset(&auth, 0, sizeof(auth));
    auth.dwVersion = SCHANNEL_CRED_VERSION;
    auth.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
    auth.paCred = &inst->credentials->context;
    auth.cCreds = 1;

    /* https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps- */
    /* This will throw an invalid argument error if the program isnt ran with administrator privilages */
    status = AcquireCredentialsHandle(0, UNISP_NAME, SECPKG_CRED_INBOUND, 0, &auth, 0, 0, &inst->credentials->handle, &inst->credentials->expiry);
    if (status != SEC_E_OK) {
        DEBUG_LOG("failed to aquire the credentials handle");
        CertFreeCertificateContext(inst->credentials->context);
        CertCloseStore(store, 0);
        return 0;
    }

    CertCloseStore(store, 0);
    return 1;

    /* http_certificate_pem_decode(); */
    /* http_certificate_der_manual_map(); */
    /* http_certificate_der_load(); */
}