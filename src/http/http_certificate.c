#include "../log.h"
#include "http.h"

int http_certificate_initialize(struct http_instance * const inst, struct http_certificate * const cred) {
    HCERTSTORE store;
    SCHANNEL_CRED auth;
    SECURITY_STATUS status;

    inst->credentials = malloc(sizeof(HTTP_CERTIFICATE));
    if (inst->credentials == NULL) {
        return 0;
    }
    
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, X509_ASN_ENCODING, 0, CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE, cred->location);
    if (store == NULL) {
        return 0;
    }
    
    /* The only method i could get working so far was to search for the issuer of the self-signed certificate */
    // inst->credentials->context = CertEnumCertificatesInStore(store, 0);
    inst->credentials->context = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_ANY, 0, 0);
    if (inst->credentials->context == NULL) {
        CertCloseStore(store, 0);
        return 0;
    }
    
    memset(&auth, 0, sizeof(auth));
    auth.dwVersion = SCHANNEL_CRED_VERSION;
    auth.grbitEnabledProtocols = SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_2_SERVER;
    auth.paCred = &inst->credentials->context;
    auth.cCreds = 1;

    /* https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps- */
    /* This will throw an invalid argument error if the program isnt ran with administrator privilages */
    status = AcquireCredentialsHandle(0, UNISP_NAME, SECPKG_CRED_INBOUND, 0, &auth, 0, 0, &inst->credentials->handle, &inst->credentials->expiry);
    if (status != SEC_E_OK) {
        CertFreeCertificateContext(inst->credentials->context);
        CertCloseStore(store, 0);
        return 0;
    }

    CertCloseStore(store, 0);
    return 1;
}