
BOOL SetConsoleColor(DWORD colorbit) {
    BYTE red   = 0;
    BYTE green = 0;
    BYTE blue  = 0;
    BYTE flags = 0;

    flags = (colorbit & 0x00FFFFFF);
    blue  = (colorbit & 0x0000FFFF);
    green = (colorbit & 0x000000FF);
    red   =  colorbit;

    return FALSE;
}

BOOL SetConsoleVTPEnabled() {
	DWORD  flags  = 0;
    HANDLE handle = NULL;
    BOOL   result = 0;

    handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if(handle == NULL) {
        return FALSE;
    }

    result = GetConsoleMode(handle, &flags);
    if(result == 0) {
        return FALSE;
    }

    result = SetConsoleMode(handle, flags | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    if(result == 0) {
        return FALSE;
    }

    return TRUE;
}


#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

//
// Idea: DebugLog(json->get_object("<hash_here>")->get_string("string"));
//

/** TODO **
 *    - Fix the depricated api warnings thrown by enet
 *    - Add SSL/TLS (Links Below)
**/

// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code
// https://learn.microsoft.com/en-us/windows/win32/winsock/using-secure-socket-extensions
// https://learn.microsoft.com/en-us/windows/win32/secauthn/secure-channel
// https://gist.github.com/mmozeiko/c0dfcc8fec527a90a02145d2cc0bfb6d

void WSA_STARTUP()
{
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
}

void WSA_CLEANUP()
{
    WSACleanup();
}

struct server {
    void (*start)();
};

struct server * server_initialize() {

};

int main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    WSA_STARTUP();

    struct server * srv = server_initialize();
    if(!srv) {

    }

    // Required to establish a connection to the server
    // UbiServices_SDK_2019.Release.27_PC64_unicode_static

    printf("Anubis Proxy 1.0.0 (tags/v1.0.0:beta)\n");
    printf("Type 'help', 'copyright', 'credits' or 'license' for more information\n");
    
    WSA_CLEANUP();
	return 0;
}

























#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/** TODO **
 *    - Fix the depricated api warnings thrown by enet
 *    - Add SSL/TLS (Links Below)
**/

// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code
// https://learn.microsoft.com/en-us/windows/win32/winsock/using-secure-socket-extensions
// https://learn.microsoft.com/en-us/windows/win32/secauthn/secure-channel
// https://gist.github.com/mmozeiko/c0dfcc8fec527a90a02145d2cc0bfb6d

int main(int argc, char* argv[])
{
    SOCKET    listener = INVALID_SOCKET;
    SOCKET    reciever = INVALID_SOCKET;
    WSADATA   data;
    INT       result = 0;
    ADDRINFO *addr;
    ADDRINFO  hint;

    (void) argc;
    (void) argv;

    result = WSAStartup(MAKEWORD(2, 2), &data);
    if(result != 0) {
        printf("%i\n", WSAGetLastError());
        return 1;
    }

    memset(&hint, 0, sizeof(hint));
    hint.ai_family    = PF_UNSPEC;
    hint.ai_flags     = AF_UNSPEC;
    hint.ai_protocol  = IPPROTO_UDP;
    hint.ai_socktype  = SOCK_DGRAM;
    
    result = getaddrinfo("127.0.0.1", "17191", &hint, &addr);
    if(result != 0) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        return 1;
    }

    listener = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if(listener == INVALID_SOCKET) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        return 1;
    }

    result = bind(listener, addr->ai_addr, (int)addr->ai_addrlen);
    if(result != 0) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        return 1;
    }

    result = listen(listener, SOMAXCONN);
    if(result != 0) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        return 1;
    }
    
    printf("listening on port '17191'\n");

    reciever = accept(listener, NULL, NULL);
    if(reciever == INVALID_SOCKET) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        return 1;
    }

    printf("connection established\n");
    closesocket(listener);
    WSACleanup();

    printf("Anubis Proxy 1.0.0 (tags/v1.0.0:beta)\n");
    printf("Type 'help', 'copyright', 'credits' or 'license' for more information\n");
    
	return 0;
}



#include <stdlib.h>
#include <stdio.h>

// Windows Sockets
#include <winsock2.h>
#include <ws2tcpip.h>

// Security Support Provider
#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h>

struct http_server {
    CHAR *port;
    CHAR *address;

    SOCKET reciever;
};

void http_server_credentials_startup();
void http_server_credentials_authenticate();
void http_server_credentials_cleanup();

void http_server_startup(struct http_server *self, int blocking) {
    int result;

    return;
}

void http_server_cleanup(struct http_server *self) {
    int result;

    return;
}

int main(int argc, char* argv[])
{
    int result;
    WSADATA data;

    result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        printf("%i\n", WSAGetLastError());
        return 1;
    }

    struct http_server server_data_handler;
    server_data_handler.port = "443";
    server_data_handler.address = "127.0.0.1";
    http_server_startup(&server_data_handler, 1);

    WSACleanup();

    // struct http_server proxy_server;
    // proxy_server.port = "0";
    // proxy_server.address = "127.0.0.1";
    // http_server_startup(&proxy_server, 1);

    // struct http_client proxy_client;
    // proxy_client.port = "0";
    // proxy_client.address = "www.growtopia1.com";
    // http_client_startup(&proxy_client, 1);


    INT result;
    WSADATA data;
    SOCKET listener = INVALID_SOCKET;
    SOCKET reciever = INVALID_SOCKET;
    SOCKADDR_IN addr;


    listener = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        goto cleanup;
    }
     
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);

    result = bind(listener, (SOCKADDR*) &addr, sizeof(addr));
    if (result != 0) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        goto cleanup;
    }

    result = listen(listener, SOMAXCONN);
    if (result != 0) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        goto cleanup;
    }

//  listen
//  get_certificate
//  get_schannel_server_handle
//  accept
//  establish_server_security_context

    //CERT_SYSTEM_STORE_CURRENT_USER
    //"Me"
    //"www.growtopia1.com"

    // Check Result
    HCERTSTORE cstore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                  0,
                  NULL,
                  CERT_SYSTEM_STORE_CURRENT_USER,
                  TEXT("Me"));

    if (cstore == NULL) {
        printf("%i:%i", __LINE__, GetLastError());
        goto cleanup;
    }

    CERT_CONTEXT* ccontext = CertFindCertificateInStore(cstore,
                               0, 
                               0,
                               CERT_FIND_SUBJECT_STR,
                               "www.growtopia1.com",
                               NULL);

    if (ccontext == NULL) {
        printf("%i:0x%x", __LINE__, GetLastError());
        goto cleanup;
    }

    CertCloseStore(cstore, 0);

    PSecPkgInfo package;
    SECURITY_STATUS status = QuerySecurityPackageInfo("Schannel", &package);
    if (status != 0) {
        printf("%i:0x%x\n", __LINE__, status);
        goto cleanup;
    }

    SCHANNEL_CRED credentials;
    
    memset(&credentials, 0, sizeof(credentials));
    credentials.dwVersion = SCHANNEL_CRED_VERSION;
    credentials.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    credentials.paCred = ccontext;
    credentials.cCreds = 1;

    CredHandle cccc;
    TimeStamp lifetime;
    status = AcquireCredentialsHandle(0, UNISP_NAME, SECPKG_CRED_INBOUND, 0, &credentials, 0, 0, &cccc, &lifetime);
    if (status != 0) {
        printf("%i:%i\n", __LINE__, status);
        goto cleanup;
    }

    reciever = accept(listener, NULL, NULL);
    if (reciever == INVALID_SOCKET) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        goto cleanup;
    }

    // while (TRUE) {
    //     recv();
    //     result = AcceptSecurityContext();
    //     switch (result) {
    //         case SEC_E_OK:
    //         case SEC_I_CONTINUE_NEEDED:
    //         case SEC_I_COMPLETE_AND_CONTINUE:
    //         case SEC_I_COMPLETE_NEEDED
    //     }
    //     send();
    //     FreeContextBuffer();
    // }

    cleanup:
    if (ccontext != NULL)
        CertFreeCertificateContext(ccontext);
    if (listener)
        closesocket(listener);
    if (reciever)
        closesocket(reciever);
    WSACleanup();

    return 0;

    (void) argc;
    (void) argv;
}


#define SECURITY_WIN32

#include <stdlib.h>
#include <stdio.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <sspi.h>
#include <schannel.h>

// Clean this
struct http_certificate {
    CHAR *name;
    CHAR *location;

    const CERT_CONTEXT *context;
    CredHandle credentials;
};

struct http_server
{
    CHAR *port;
    CHAR *address;
    SOCKET listener;
    SOCKET reciever;
    INT queue;
};

void http_server_alloc(struct http_server *self);
void http_server_free(struct http_server *self);
int http_server_startup(struct http_server *self);
int http_server_cleanup(struct http_server *self);
int http_server_listen(struct http_server *self);
int http_server_accept(struct http_server *self);
int http_server_authorize(struct http_server *self);
int http_server_credentials_initialize(struct http_server *self);

int main(int argc, char **argv)
{
    struct http_credentials *credentials;
    struct http_server *server;
    http_server_alloc(server);
    http_server_credentials_alloc(server);

    if (server == NULL) {
        return 1;
    }

    server->port = "443";
    server->address = "127.0.0.1";
    server->queue = 1;
    server->certificate->name = "www.growtopia1.com";
    server->certificate->location = "Me";

    if (http_server_startup(server) && http_server_credentials_initialize(htt)) {
        http_server_listen(server);
        http_server_accept(server);
        http_server_authenticate(server);

        while (TRUE) {

        }
    }

    http_server_cleanup(server);
    http_server_free(server);

    return 0;

    (void) argc;
    (void) argv;
}


void http_server_alloc(struct http_server *self) {
    self = malloc(sizeof(struct http_server));
    self->certificate = malloc(sizeof(struct http_server_certificate));
}

void http_server_free(struct http_server *self) {
    if (self != NULL) {
        if (self->certificate != NULL)
            free(self->certificate);
        free(self);
    }
}

int http_server_startup(struct http_server *self)
{
    int ret    = 0;
    int result = 0;
    ADDRINFO  hint;
    ADDRINFO *addr;

    hint.ai_addr      = 0;
    hint.ai_addrlen   = 0;
    hint.ai_canonname = 0;
    hint.ai_family    = AF_UNSPEC;
    hint.ai_flags     = AF_UNSPEC;
    hint.ai_next      = 0;
    hint.ai_protocol  = IPPROTO_TCP;
    hint.ai_socktype  = SOCK_STREAM;

    result = getaddrinfo(self->address, self->port, &hint, &addr);
    if (result != 0) {
        return 0;
    }

    self->listener = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (self->listener == INVALID_SOCKET) {
        freeaddrinfo(addr);
        return 0;
    }

    result = bind(self->listener, addr->ai_addr, addr->ai_addrlen);
    if (result != 0) {
        freeaddrinfo(addr);
        closesocket(self->listener);
        return 0;
    }
    
    freeaddrinfo(addr);
    return ret;
}

int http_server_listen(struct http_server *self)
{
    int result;

    if (self->queue > SOMAXCONN) {
        return 0;
    }

    result = listen(self->listener, self->queue);
    if (result != 0) {
        return 0;
    }

    return 1;
}

int http_server_accept(struct http_server *self)
{
    self->reciever = accept(self->listener, NULL, NULL);
    if (self->reciever == INVALID_SOCKET) {
        return 0;
    }

    return 1;
}

int http_server_cleanup(struct http_server *self)
{
    // check return values later
    closesocket(self->reciever);
    FreeCredentialHandle(&self->certificate->credentials);
    CertFreeCertificateContext(self->certificate->context);
    closesocket(self->listener);
    return 1;
}

int http_server_credentials_initialize(struct http_server *self)
{
    HCERTSTORE store;
    SCHANNEL_CRED auth;
    TimeStamp lifetime;
    SECURITY_STATUS status;
    
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, self->certificate->location);
    if (store == NULL) {
        return 0;
    }

    self->certificate->context = CertFindCertificateInStore(store, 0, 0, CERT_FIND_SUBJECT_NAME, self->certificate->name, NULL);
    if (self->certificate->context == NULL) {
        CertCloseStore(store, 0);
        return 0;
    }

    memset(&self->certificate->credentials, 0, sizeof(self->certificate->credentials));
    auth.dwVersion = SCHANNEL_CRED_VERSION;
    auth.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    auth.paCred = &self->certificate->context;
    auth.cCreds = 1;

    // https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps-
    status = AcquireCredentialsHandleW(0, UNISP_NAME, SECPKG_CRED_INBOUND, 0, &auth, 0, 0, &self->certificate->credentials, &lifetime);
    if (status != 0) {
        CertFreeCertificateContext(self->certificate->context);
        CertCloseStore(store, 0);
        return 0;
    }

    CertCloseStore(store, 0);
    return 1;
}

int http_server_credentials_accept(struct http_server *self)
{
    CtxtHandle *context = NULL;
    TimeStamp lifetime;
    ULONG flags = 0;
    SecBufferDesc desc_in;
    CHAR desc_in_token[4096];
    SecBuffer desc_in_buffers[2];
    SecBufferDesc desc_out;
    SecBuffer desc_out_buffers[1];

    desc_in_buffers[0].BufferType = SECBUFFER_TOKEN;
    desc_in_buffers[0].cbBuffer = 4096;
    desc_in_buffers[0].pvBuffer = desc_in_token;
    desc_in_buffers[1].BufferType = SECBUFFER_EMPTY;
    desc_in_buffers[1].cbBuffer = 0;
    desc_in_buffers[1].pvBuffer = 0;
    desc_in.cBuffers = 2;
    desc_in.pBuffers = desc_in_buffers;
    desc_in.ulVersion = SECBUFFER_VERSION;

    desc_out_buffers[0].BufferType = SECBUFFER_EMPTY;
    desc_out_buffers[0].cbBuffer = 0;
    desc_out_buffers[0].pvBuffer = 0;
    desc_out.cBuffers = 1;
    desc_out.pBuffers = desc_out_buffers;
    desc_out.ulVersion = SECBUFFER_VERSION;

    while (1) {
        AcceptSecurityContext(&self->certificate->credentials, context, &desc_in, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR, 
        0, 0, &desc_out, &flags, &lifetime);
        // CompleteAuthToken();
        // FreeContextBuffer();
        // revc();
        // send();
    }
}




// && http_server_credentials_initialize(&server, &credentials)


    // http_server_cleanup(&server);

    
        // AcceptSecurityContext();
        // CompleteAuthToken();
        // FreeContextBuffer();
        // recv();
        // send();


        
int http_server_credentials_initialize(struct http_server *self)
{
    HCERTSTORE store;
    SCHANNEL_CRED auth;
    TimeStamp lifetime;
    SECURITY_STATUS status;
    
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, self->certificate->location);
    if (store == NULL) {
        return 0;
    }

    self->certificate->context = CertFindCertificateInStore(store, 0, 0, CERT_FIND_SUBJECT_NAME, self->certificate->name, NULL);
    if (self->certificate->context == NULL) {
        CertCloseStore(store, 0);
        return 0;
    }

    memset(&self->certificate->credentials, 0, sizeof(self->certificate->credentials));
    auth.dwVersion = SCHANNEL_CRED_VERSION;
    auth.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    auth.paCred = &self->certificate->context;
    auth.cCreds = 1;

    // https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps-
    status = AcquireCredentialsHandle(0, UNISP_NAME, SECPKG_CRED_INBOUND, 0, &auth, 0, 0, &self->certificate->credentials, &lifetime);
    if (status != 0) {
        CertFreeCertificateContext(self->certificate->context);
        CertCloseStore(store, 0);
        return 0;
    }

    CertCloseStore(store, 0);
    return 1;
}

int http_server_credentials_accept(struct http_server *self)
{
    CtxtHandle *context = NULL;
    TimeStamp lifetime;
    ULONG flags = 0;
    SecBufferDesc desc_in;
    CHAR desc_in_token[4096];
    SecBuffer desc_in_buffers[2];
    SecBufferDesc desc_out;
    SecBuffer desc_out_buffers[1];

    desc_in_buffers[0].BufferType = SECBUFFER_TOKEN;
    desc_in_buffers[0].cbBuffer = 4096;
    desc_in_buffers[0].pvBuffer = desc_in_token;
    desc_in_buffers[1].BufferType = SECBUFFER_EMPTY;
    desc_in_buffers[1].cbBuffer = 0;
    desc_in_buffers[1].pvBuffer = 0;
    desc_in.cBuffers = 2;
    desc_in.pBuffers = desc_in_buffers;
    desc_in.ulVersion = SECBUFFER_VERSION;

    desc_out_buffers[0].BufferType = SECBUFFER_EMPTY;
    desc_out_buffers[0].cbBuffer = 0;
    desc_out_buffers[0].pvBuffer = 0;
    desc_out.cBuffers = 1;
    desc_out.pBuffers = desc_out_buffers;
    desc_out.ulVersion = SECBUFFER_VERSION;

    while (1) {
        AcceptSecurityContext(&self->certificate->credentials, context, &desc_in, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR, 
        0, 0, &desc_out, &flags, &lifetime);
        // CompleteAuthToken();
        // FreeContextBuffer();
        // revc();
        // send();
    }
}


#ifndef __HTTP_H_
#define __HTTP_H_

#define SECURITY_WIN32

/* Winsock */
#include <winsock2.h>
#include <ws2tcpip.h>

/* Secure Socket Protocol Interface */
#include <sspi.h>
#include <schannel.h>

#define DEBUG
#if defined(DEBUG)
#include <stdio.h>
#define DEBUG_LOG(T) printf("[%i:%s()]: %s\n", __LINE__, __FUNCTION__, T)
#else
#define DEBUG_LOG(T)
#endif


typedef struct http_certificate_data {
    char *name;
    char *issuer;
    char *location;
} HTTP_CERTIFICATE_DATA;

typedef struct http_certificate {
    HTTP_CREDENTIALS_DATA public;
    HTTP_CREDENTIALS_DATA private;
} HTTP_CERTIFICATE;

typedef struct http_credentials {
    PCCERT_CONTEXT context;
    CredHandle credentials;
    TimeStamp expiry;
} HTTP_credentials;

typedef struct http_instance {
    char *port;
    char *address;
    int   queue;

    SOCKET listener;
    SOCKET reciever;
    HTTP_CERTIFICATE *certificate;
} HTTP_INSTANCE;

int http_server_initialize(struct http_instance * const inst);
int http_server_listen(struct http_instance * const inst);
int http_server_accept(struct http_instance * const inst);
int http_server_authenticate(struct http_instance * const inst);
int http_certificate_initialize(struct http_instance * const inst, struct http_credentials * const cred);

#endif


#include "http.h"

// The easiest method is to load a cert directly from memory, but that is cheating compared to an actual system
int http_certificate_initialize(struct http_instance * const inst, struct http_certificate * const cred) {
    HCERTSTORE store;
    SCHANNEL_CRED auth;
    SECURITY_STATUS status;

    inst->certificate = malloc(sizeof(HTTP_CERTIFICATE));
    if (inst->certificate == NULL) {
        DEBUG_LOG("failed to allocate memory");
        return 0;
    }
    
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE, cred->location);
    if (store == NULL) {
        DEBUG_LOG("could not open the store");
        return 0;
    }
    
    /* The only method i could get working so far was to search for the issuer of the self-signed certificate */
    inst->certificate->context = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR_A, cred->issuer, NULL);
    if (inst->certificate->context == NULL) {
        DEBUG_LOG("could not find the certificate in the store");
        CertCloseStore(store, 0);
        return 0;
    }
    
    memset(&auth, 0, sizeof(auth));
    auth.dwVersion = SCHANNEL_CRED_VERSION;
    auth.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
    auth.paCred = &inst->certificate->context;
    auth.cCreds = 1;

    /* https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps- */
    /* This will throw an invalid argument error if the program isnt ran with administrator privilages */
    status = AcquireCredentialsHandle(0, UNISP_NAME, SECPKG_CRED_INBOUND, 0, &auth, 0, 0, &inst->certificate->credentials, &inst->certificate->expiry);
    if (status != SEC_E_OK) {
        DEBUG_LOG("failed to aquire the credentials handle");
        CertFreeCertificateContext(inst->certificate->context);
        CertCloseStore(store, 0);
        return 0;
    }

    CertCloseStore(store, 0);
    return 1;
}

/* fix these struct names */
typedef struct http_blob {
    char **file;
    long   file_length;
    void  *key;
    long   key_length;
} HTTP_BLOB;

int http_certificate_load_file(struct http_credentials_file * const cred, struct http_blob * const blob) {

}

int http_certificate_decode_file(struct http_credentials_file * const cred, struct http_blob * const blob) {
    unsigned char *binary;
    long binary_length;
    void *decode;
    long decode_length;

    /* Check return values */
    CryptStringToBinaryW(blob->file, blob->file_length, CRYPT_STRING_BASE64HEADER, binary, &binary_length, 0, 0);
    DecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &binary, binary_length, CRYPT_DECODE_ALLOC_FLAG, 0, &decode, &decode_length);
    DecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, &decode, decode_length, CRYPT_DECODE_ALLOC_FLAG, 0, &blob->key, &blob->key_length);
    LocalFree(decode);
}

int http_certificate_initialize_from_file(struct http_instance * const inst, struct http_credentials_file * const cred) {
    unsigned int length;
    void * file;
    struct http_blob blob;

    length = strlen(cred->public);
    if (length > 0) {
        file = CreateFile(cred->public, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (file == INVALID_HANDLE_VALUE) {
            DEBUG_LOG();
            return 0;
        }
    }

    length = strlen(cred->private);
    if (length > 0) {

    }
}

/* Load a certificate from the disk */
int http_certificate_initialize_from_file(struct http_instance * const inst, struct http_credentials * const cred) {
    HANDLE  file;
    DWORD   read;
    DWORD   result;
    CHAR   *buffer;
    DWORD   buffer_length;
    BYTE   *binary;
    DWORD   binary_length;
    VOID   *binary_decoded;
    DWORD   binary_decoded_length;
    VOID   *binary_decoded_rsa;
    DWORD   binary_decoded_rsa_length;
    SCHANNEL_CRED auth;
    SECURITY_STATUS status;

    inst->certificate = malloc(sizeof(HTTP_CERTIFICATE));
    if (inst->certificate == NULL) {
        DEBUG_LOG("failed to allocate memory");
        return 0;
    }

    file = CreateFile(cred->name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        DEBUG_LOG("failed to get a handle to the file");
        return 0;
    }

    buffer_length = GetFileSize(file, NULL);
    if (buffer_length == 0) {
        DEBUG_LOG("failed to get the file size");
        CloseHandle(file);
        return 0;
    }

    buffer = malloc(sizeof(CHAR) * buffer_length);
    if (buffer == NULL) {
        DEBUG_LOG("failed to allocate memory");
        CloseHandle(file);
        return 0;
    }

    result = ReadFile(file, buffer, buffer_length, &read, 0);
    if (result == 0) {
        DEBUG_LOG("failed to read the file from disk");
        free(buffer);
        CloseHandle(file);
        return 0;
    }

    CloseHandle(file);

    inst->certificate->context = CertCreateCertificateContext(X509_ASN_ENCODING, buffer, buffer_length);
    if (inst->certificate->context == NULL) {
        DEBUG_LOG("failed to create a certificate context");
        free(buffer);
        return 0;
    }
    
    CryptStringToBinary(buffer, buffer_length, CRYPT_STRING_BASE64HEADER, NULL, &binary_length, 0, 0);
    if (binary_length == 0) {
        DEBUG_LOG("could not determine the required length for the certificate");
        free(buffer);
        return 0;
    }

    binary = malloc(sizeof(BYTE) * binary_length);
    result = CryptStringToBinary(buffer, buffer_length, CRYPT_STRING_BASE64HEADER, binary, &binary_length, 0, 0);
    if (result == 0) {
        DEBUG_LOG("failed to extract the certificate from the certificate file");
        free(buffer);
        free(binary);
        return 0;
    }

    result = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &binary, binary_length, CRYPT_DECODE_ALLOC_FLAG, 0, &binary_decoded, &binary_decoded_length);
    if (result == 0) {
        DEBUG_LOG("failed to decode the certificate");
        free(buffer);
        free(binary);
        return 0;
    }

    result = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, &binary_decoded, binary_decoded_length, CRYPT_DECODE_ALLOC_FLAG, 0, &binary_decoded_rsa, &binary_decoded_rsa_length);
    if (result == 0) {
        DEBUG_LOG("failed to decode the certificate");
        free(buffer);
        free(binary);
        return 0;
    }

    memset(&auth, 0, sizeof(auth));
    auth.dwVersion = SCHANNEL_CRED_VERSION;
    auth.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    auth.paCred = &inst->certificate->context;
    auth.cCreds = 1;

    /* https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps- */
    /* This will throw an invalid argument error if the program isnt ran with administrator privilages */
    status = AcquireCredentialsHandle(0, UNISP_NAME, SECPKG_CRED_INBOUND, 0, &auth, 0, 0, &inst->certificate->credentials, 0);
    if (status != SEC_E_OK) {
        DEBUG_LOG("failed to aquire the credentials handle");
        CertFreeCertificateContext(inst->certificate->context);
        free(buffer);
        free(binary);
        return 0;
    }

    free(binary);
    free(buffer);
    return 1;
}



    unsigned char *binary;
    long binary_length;
    void *decode;
    long decode_length;

    /* Check return values */
    CryptStringToBinaryW(blob->file, blob->file_length, CRYPT_STRING_BASE64HEADER, binary, &binary_length, 0, 0);
    DecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &binary, binary_length, CRYPT_DECODE_ALLOC_FLAG, 0, &decode, &decode_length);
    DecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, &decode, decode_length, CRYPT_DECODE_ALLOC_FLAG, 0, &blob->key, &blob->key_length);
    LocalFree(decode);


    

/* fix these struct names */
typedef struct http_blob {
    char **file;
    long   file_length;
    void  *key;
    long   key_length;
} HTTP_BLOB;

int http_certificate_load_file(struct http_certificate_file * const cert, struct http_blob * const blob) {

}

int http_certificate_decode_key(struct http_blob * const blob) {
}



#include "http.h"

/* Rewrite this */
int http_certificate_initialize(struct http_instance * const inst, struct http_certificate * const cred) {
    HCERTSTORE store;
    SCHANNEL_CRED auth;
    SECURITY_STATUS status;

    inst->credentials = malloc(sizeof(HTTP_CERTIFICATE));
    if (inst->credentials == NULL) {
        DEBUG_LOG("failed to allocate memory");
        return 0;
    }
    
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE, cred->location);
    if (store == NULL) {
        DEBUG_LOG("could not open the store");
        return 0;
    }
    
    /* The only method i could get working so far was to search for the issuer of the self-signed certificate */
    inst->credentials->context = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR_A, cred->issuer, NULL);
    if (inst->credentials->context == NULL) {
        DEBUG_LOG("could not find the certificate in the store");
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
}

int http_certificate_initialize_from_file(struct http_instance * const inst, struct http_certificate_file * const cert) {
    HTTP_CERTIFICATE_BLOB blob;

    if (inst == NULL ||
        cert == NULL) {
        return 0;
    }

    if (http_certificate_load_file(cert, &blob) == 0) {
        printf("Failed to load the certificate from the file\n");
        return 0;
    }

    if (http_certiticate_blob_decode(&blob) == 0) {
        printf("Failed to decode the certificate blob\n");
        return 0;
    }

    if (http_certificate_blob_get_context(inst, &blob)) {
        printf("Failed to obtain a certificate context\n");
        return 0;
    }
    
    return 1;
}

int http_certificate_initialize_from_resource(struct http_instance * const inst, struct http_certificate_resource * const cert) {
    HTTP_CERTIFICATE_BLOB blob;

    if (inst == NULL ||
        cert == NULL) {
        return 0;
    }
    
    if (http_certificate_load_resource(cert, &blob) == 0) {
        printf("Failed to load the resource data\n");
        return 0;
    }

    if (http_certiticate_blob_decode(&blob) == 0) {
        printf("Failed to decode the certificate blob\n");
        return 0;
    }

    if (http_certificate_blob_get_context(inst, &blob)) {
        printf("Failed to obtain a certificate context\n");
        return 0;
    }

    return 1;
}

int http_certificate_load_file(struct http_certificate_file * const cert, struct http_certificate_blob * const blob) {
    BOOL  result;
    void *file;
    long  length;

    if (blob == NULL) {
        return 0;
    }

    file = CreateFile(cert->location, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }

    length = GetFileSize(file, NULL);
    if (length == 0) {
        CloseHandle(file);
        return 0;
    }

    result = ReadFile(file, blob->in.data, length, &blob->in.length, 0);
    if (result == FALSE) {
        CloseHandle(file);
        return 0;
    }

    CloseHandle(file);
    return 1;
}

int http_certificate_load_resource(struct http_certificate_resource * const cert, struct http_certificate_blob * const blob) {
    HRSRC resource;
    HGLOBAL handle;

    resource = FindResource(NULL, MAKEINTRESOURCE(cert->private), RT_RCDATA);
    if (resource == NULL) {
        printf("no resource:0x%x\n", GetLastError());
        return 0;
    }

    handle = LoadResource(NULL, resource);
    if (handle == NULL) {
        printf("bad handle\n");
        return 0;
    }

    blob->in.data = LockResource(handle);
    blob->in.length = SizeofResource(NULL, resource);

    FreeResource(handle);
    
    if (blob->in.data == NULL ||
        blob->in.length == 0) {
        return 0;
    }

    return 1;
}

int http_certiticate_blob_decode(struct http_certificate_blob * const blob) {
    void *binary;
    long  length;
    void *t;
    long  a;
    BOOL result;

    if (blob == NULL) {
        return 0;
    }
    
    result = CryptStringToBinary(blob->in.data, 0, CRYPT_STRING_BASE64HEADER, binary, &length, 0, 0);
    if (result == FALSE) {
        return 0;
    }
    
    // result = CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, binary, binary_length, CRYPT_DECODE_ALLOC_FLAG, 0, &blob->out.data, &blob->out.length);
    //    if (CryptDecodeObjectEx(
    //         PKCS_7_ASN_ENCODING,
    //         PKCS_PRIVATE_KEY_INFO,
    //         prvkeybuf, prvkeylen,
    //         CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
    //         NULL,
    //         &inf, &len)) {
    //     /*
    //      * decode the key, first with a NULL
    //      * output buffer to get the size
    //      */
    //     if (CryptDecodeObject(
    //             PKCS_7_ASN_ENCODING,
    //             PKCS_RSA_PRIVATE_KEY,
    //             inf->PrivateKey.pbData, inf->PrivateKey.cbData,
    //             0,
    //             NULL, &len)) {

    result = CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, binary, length, 0, 0, &blob->out.length);
    if (result == FALSE) {
        printf("0x%x\n", GetLastError());
        return 0;
    }

    blob->out.data = LocalAlloc(0, blob->out.length);
    if (blob->out.data == NULL) {
        return 0;
    }

    result = CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, binary, length, 0, &blob->out.data, &blob->out.length);
    if (result == FALSE) {
        printf("0x%x\n", GetLastError());
        return 0;
    }


    // result = CryptDecodeObjectEx(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, decode, decode_length, CRYPT_DECODE_ALLOC_FLAG, 0, &blob->out.data, &blob->out.length);
    // if (result == FALSE) {
    //     return 0;
    // }
    
    /* LocalFree(decode); */
    return 1;
}

int http_certificate_blob_get_context(struct http_instance * const inst, struct http_certificate_blob * const blob) {
    SCHANNEL_CRED auth;
    SECURITY_STATUS status;

    if (inst == NULL ||
        blob == NULL) {
        return 0;
    }
    
    inst->credentials->context = CertCreateCertificateContext(X509_ASN_ENCODING, blob->out.data, blob->out.length);
    if (inst->credentials->context == NULL) {
        return 0;
    }

    memset(&auth, 0, sizeof(auth));
    auth.dwVersion = SCHANNEL_CRED_VERSION;
    auth.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    auth.paCred = &inst->credentials->context;
    auth.cCreds = 1;

    /* https://learn.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps- */
    /* This will throw an invalid argument error if the program isnt ran with administrator privilages */
    status = AcquireCredentialsHandle(0, UNISP_NAME, SECPKG_CRED_INBOUND, 0, &auth, 0, 0, &inst->credentials->handle, 0);
    if (status == 0) {
        return 0;
    }

    return 1;
}


/// ServerData
#include <windows.h>
#include <wininet.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
	INT result = 0;
	HINTERNET instance = NULL;
	HINTERNET server = NULL;
	HINTERNET request = NULL;
	DWORD     length;
	WCHAR *   buffer = NULL;
	DWORD     bytes;

	result = InternetAttemptConnect(0);
	if (result != 0)
		goto cleanup;
	
	instance = InternetOpen("UbiServices", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (instance == NULL)
		goto cleanup;
	
	server = InternetConnect(instance, "www.growtopia1.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, INTERNET_NO_CALLBACK);
	if (server == NULL)
		goto cleanup;

	request = HttpOpenRequest(server, "POST", "/growtopia/server_data.php", NULL, "", NULL, INTERNET_FLAG_SECURE, 0);
	if (request == NULL)
		goto cleanup;

	result = HttpSendRequest(request, NULL, -1, NULL, 0);
	if (result == 0)
		goto cleanup;

	while(TRUE) {
		result = InternetQueryDataAvailable(request, &length, 0, 0);

		if(result != 0)
			break;
	
		Sleep(5000);
	}
	
	buffer = malloc(sizeof(WCHAR) * (length + 1));
	if (buffer == NULL)
		goto cleanup;

	while(TRUE) {
		result = InternetReadFile(request, buffer, length, &bytes);

		if (result == FALSE)
			break;

		if (bytes == 0)
			break;

		// add something to remove any garbage later on
		printf("%s", buffer);
	}

	cleanup:

	if (buffer)
		free(buffer);
	if (request)
		InternetCloseHandle(request);
	if (server)
		InternetCloseHandle(server);
	if (instance)
		InternetCloseHandle(instance);


	return 0;
    (void) argc;
    (void) argv;
}



#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define SECURITY_WIN32
#include <sspi.h>

#include <schannel.h>

/** TODO **
 *    - Fix the depricated api warnings thrown by enet
 *    - Add SSL/TLS (Links Below)
**/

// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code
// https://learn.microsoft.com/en-us/windows/win32/winsock/using-secure-socket-extensions
// https://learn.microsoft.com/en-us/windows/win32/secauthn/secure-channel
// https://gist.github.com/mmozeiko/c0dfcc8fec527a90a02145d2cc0bfb6d

INT recive(SOCKET sock, CHAR * buf, DWORD len)
{
    LPCTSTR;
    CHAR * buffer    = buf;
    DWORD  remaining = len;
    DWORD  count     = 0;

    while (remaining) {
        count = recv(sock, buffer, remaining, 0);

        if (count == SOCKET_ERROR) {
            printf("%i:%i", __LINE__, WSAGetLastError());
            return 0;
        }

        remaining = remaining - count;
        buffer = buffer + count;
    }

    return len - remaining;
}

int main(int argc, char* argv[])
{
    SECURITY_STATUS status;
    PSecPkgInfo     package;
    SCHANNEL_CRED   credentialhints;
    CredHandle      credentials;
    TimeStamp       lifetime;
    INT         result = 0;
    WSADATA     data;
    SOCKET      listener = INVALID_SOCKET;
    SOCKET      reciever = INVALID_SOCKET;
    SOCKADDR_IN addr;
    CHAR       *buffer;
    INT         length;
        
    result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        printf("%i\n", WSAGetLastError());
        return 1;
    }

    status = QuerySecurityPackageInfo("Schannel", &package);
    if (status != 0) {
        printf("%i:%i\n", __LINE__, status);
        goto cleanup;
    }

    listener = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        goto cleanup;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0;
    addr.sin_port = htons(443);

    result = bind(listener, (SOCKADDR*) &addr, sizeof(addr));
    if (result != 0) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        goto cleanup;
    }

    result = listen(listener, SOMAXCONN);
    if (result != 0) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        goto cleanup;
    }

    reciever = accept(listener, NULL, NULL);
    if (reciever == INVALID_SOCKET) {
        printf("%i:%i\n", __LINE__, WSAGetLastError());
        goto cleanup;
    }

    printf("connection established\n");
    printf("attempting to authenticate\n");

    status = AcquireCredentialsHandle(NULL, package->Name, SECPKG_CRED_INBOUND, NULL, credentialhints, NULL, NULL, &credentials, &lifetime);
    if (status < 0) {
        printf("%i:0x%x\n", __LINE__, status);
    //     SEC_E_INSUFFICIENT_MEMORY; 0x80090300L;
    //     SEC_E_INTERNAL_ERROR; 0x80090304L;
    //     SEC_E_NO_CREDENTIALS; 0x8009030EL;
    //     SEC_E_NOT_OWNER; 0x80090306L;
    //     SEC_E_SECPKG_NOT_FOUND; 0x80090305L;
    //     SEC_E_UNKNOWN_CREDENTIALS; 0x8009030DL;
    }

   while (TRUE) {
        buffer = malloc(sizeof(CHAR) * 512);
        if (buffer == NULL)
            goto cleanup;

        length = recive(reciever, (char*)buffer, 512);
        if (length == 0)
            goto cleanup;
    }

    printf("authentication successful\n");
    
    cleanup:
    if (buffer)
        free(buffer);
    if (listener)
        closesocket(listener);
    if (reciever)
        closesocket(reciever);

    FreeContextBuffer(package);
    WSACleanup();
    
	return 0;

    (void) argc;
    (void) argv;
}



	// struct http_certificate_resource certificate;

	// certificate.public = GROWTOPIA_CERT_CRT;
	// certificate.private = GROWTOPIA_CERT_PEM;

	
	// if (http_certificate_initialize_from_resource(&server, &certificate) == 0) {
	// 	return 0;
	// }

    
int http_certiticate_blob_decode(struct http_certificate_blob * const blob);
int http_certificate_blob_get_context(struct http_instance * const inst, struct http_certificate_blob * const blob);
int http_certificate_load_file(struct http_certificate_file * const cert, struct http_certificate_blob * const blob);
int http_certificate_load_resource(struct http_certificate_resource * const cert, struct http_certificate_blob * const blob);

int http_certificate_initialize(struct http_instance * const inst, struct http_certificate * const cred);
int http_certificate_initialize_from_file(struct http_instance * const inst, struct http_certificate_file * const cert);
int http_certificate_initialize_from_resource(struct http_instance * const inst, struct http_certificate_resource * const cert);







#include <stdlib.h>
#include <stdio.h>

#include "log.h"
#include "http/http.h"
#include "../res/resource.h"

const char * const base64_crt = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUQxRENDQXJ5Z0F3SUJBZ0lFZE5jN2NEQU5CZ2txaGtpRzl3MEJBUXNGQURDQmdqRUxNQWtHQTFVRUJoTUMKVkZJeEd6QVpCZ05WQkFNTUVuZDNkeTVuY205M2RHOXdhV0V4TG1OdmJURUxNQWtHQTFVRUNBd0NXRmd4Q3pBSgpCZ05WQkFjTUFuaDRNUkl3RUFZRFZRUUtEQWxJWlhsVGRYSm1aWEl4S0RBbUJna3Foa2lHOXcwQkNRRVdHV2hsCmVYTjFjbVpsY25OQWNISnZkRzl1YldGcGJDNWpiMjB3SGhjTk1qTXdNek13TVRrek9EUXdXaGNOTXpNd016STMKTVRrek9EUXdXakNCZ2pFTE1Ba0dBMVVFQmhNQ1ZGSXhHekFaQmdOVkJBTU1FbmQzZHk1bmNtOTNkRzl3YVdFeApMbU52YlRFTE1Ba0dBMVVFQ0F3Q1dGZ3hDekFKQmdOVkJBY01Bbmg0TVJJd0VBWURWUVFLREFsSVpYbFRkWEptClpYSXhLREFtQmdrcWhraUc5dzBCQ1FFV0dXaGxlWE4xY21abGNuTkFjSEp2ZEc5dWJXRnBiQzVqYjIwd2dnRWkKTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEQlA1azBaSitkajQwL2ZGZ1pXYUV3bGx2egpNL3JTYjFNbnVvS2ZuOXQ0aDdlQXJpcVQ4dHhGak9WU05kSE0vNXQ2eTRqb1pyZFJkczMzZnArZGY0eVdaSEJXCmhhUFM2TTFDcU16a092WEpxbXAvQTNwNzFIOHdmRk1hMUo2VC96cjJta0hrZ2ZtckFQaktMV2FFWUovUHJRVVkKdnZpTW5YcTRkVEFyTGNVMnFOcHBmUHNYeWhMR21NTEpEdTlucjV5NDI4YXZHN2xJYlpzdGZVODUxT1FEVDhYTgpOaFp4aC9JTVVaQkpTRjcxVFV1UXBuQzVmSlJ4eTFCZkFrWUZpMWY1MEtsVFVlRW1hMkRva0U1cVB6TWllelZtCmdHWXNMSFFjSXR3aXU1YlRoNHJpdStVVHRMTmNKUjcvcWhLVkxXOCt5MFJVSUdwRG1LdGdzMEszNUZickFnTUIKQUFHalVEQk9NQjBHQTFVZERnUVdCQlQ5QUh5VVVpVThvYzRCTEQ2aTUraUxTdWVkempBZkJnTlZIU01FR0RBVwpnQlQ5QUh5VVVpVThvYzRCTEQ2aTUraUxTdWVkempBTUJnTlZIUk1FQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCCkN3VUFBNElCQVFCZXdhMGNWb1VlTHZwWisySktCaC9mR3g5cXRnRFJsYkNPTGg0ZFAxQU9MYTZwaUhZUXQxUFcKRGZaUWZwYXBsZUtVOVRjbVYxMHZNeHNBVmQrSWJ2NXdwS0Rnd1NHV1dleDFuYzhsTDNKZW5xaC9HODg4QVBxegpBbWtTd2R0dk1lUUY0TnVaZndZZDZKWmpzbE9WNVJaSW1oRmFTOWI3b21XYUZXQUdtbjR5Skd3MGdNYUE3TEs3CkhzQmwwdGc2ZG9qNHdYSEkwMWJ1enpibEpuVlBPSzZDZkxyZGVxOWFRT3pqYlBoN003dDZMaEZocmVCZnJIeFAKN3FjQUhhR25GbFg0bm9FYzlIbUtaYTJYL3N1NFVYWTRiYkZWVE1OSytzbmJwR29aNitmRDN3dHhiMVZXY3k1bAplRnJmSjBINUlud0lRQU1ITUZBOTRVcnFBU1U5WkpCOAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t";
const char * const base64_key = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRREJQNWswWkorZGo0MC8KZkZnWldhRXdsbHZ6TS9yU2IxTW51b0tmbjl0NGg3ZUFyaXFUOHR4RmpPVlNOZEhNLzV0Nnk0am9acmRSZHMzMwpmcCtkZjR5V1pIQldoYVBTNk0xQ3FNemtPdlhKcW1wL0EzcDcxSDh3ZkZNYTFKNlQvenIybWtIa2dmbXJBUGpLCkxXYUVZSi9QclFVWXZ2aU1uWHE0ZFRBckxjVTJxTnBwZlBzWHloTEdtTUxKRHU5bnI1eTQyOGF2RzdsSWJac3QKZlU4NTFPUURUOFhOTmhaeGgvSU1VWkJKU0Y3MVRVdVFwbkM1ZkpSeHkxQmZBa1lGaTFmNTBLbFRVZUVtYTJEbwprRTVxUHpNaWV6Vm1nR1lzTEhRY0l0d2l1NWJUaDRyaXUrVVR0TE5jSlI3L3FoS1ZMVzgreTBSVUlHcERtS3RnCnMwSzM1RmJyQWdNQkFBRUNnZ0VBTDhvWmloSmtRcU93YTRYRmg2ZFpyRmxTcmVjcDNRWjR5dmRkdkRuZEhZWjYKZzlFT2FINERxUk41MW9YR3QycHl1Y0JCd0M4K29GKy8rYmVQbzNSYWdRcWZtVlg5T0hnbjRwYzU3Q3NFZzNXbwpWbmEyd0k3QlVXMDlaQUkyb1NUYUlRZnV5YUsyNm1vWUhHOXp6Y0xUWXBsSURHR1Z0N2h1RTlXdkxzNW4yZWNqCngxUzJEVWg1eDJ2NmRNRVdueG5nckxqZC9ZN0xYaFV0am8zbHh0dE56S0tLaGZmNUFYcmFwWGNjOVdoK2tLa3gKZ3d1cW1OM2xucDg1UVkvTnJFWkY1WmlzajVYbjM5WkFqaGxTaS95NmxlSHFpdmJicXVreTlqREtwNTdVZVVlVApBWEJPZ2xIWEZySXlrVUl3cFZKbGVuVnhsRFQ3QXFCdmVndHZtR2hPQVFLQmdRRHErSU1jUmR3WlU4cEtvNy8zCjVJdXlJZk82V3FHemZ1WnBDejB0NnVIcDNHYVQ2TnQ4N3dZNkxRZ0E2Yk1Uc0FuUDBrS2E2THRxRHdQSW55RHcKcXFZZTkzOXRNWEJrdzBsdlQzc3NIK0JYclhNR0ZFOVl0WkpzUWdIK3R2eWV5ck5pTCs1THdmSDgrZXJ3YVNxRwpYeWNCZXlGSXFoZ1NqbEE4OUFxdTIxWGxBUUtCZ1FEU2l5eGM3cnVGcXdMaGxmeHBzaXY5MGJCenVMZ2QwSGcyCkltS3ZqVk1waWpaMjlWT09JVGs2NUZ5T05rbEZINlJuR0ZQYkRSb1dYVlVYdnZxYVRVTzl1ZUtobllHRkpGL2YKVFJOcTloeTZSdEpnejRvZFB5MUhtTjFiVmxYUTJBRHZaRU1pbHVTQ044KzdJVnlQMWdDeXR1OFdvZ1B1cEVlZgp4enRyYVZBZjZ3S0JnUURWTkUxek9BaHdpdEVCVFBnQkxNVjlDc1dta0ZvdERyWnZGaDJiTG9keXRlUDF6ZEpxCjJFL2tOYndQWi81dm5Nb3FZblRCTHUvdldsUnFrOGxGMXZJSkl6WGlsSHVSVW9tdGtJY0pFSnQxc3hLdHIzd1gKMkJsV1ZjYU5vdWd5QldjamJxNWcyMGlCN1JzNnJaSkNmdEJiemFmejBUTXFreXRIUTREMkRGc3lBUUtCZ1FDOQoyUjdrb2FSWDhJOUZpUEExQXFNbVdXbEp2OXZOam9pSEQ5UjZ4ZTJpUEczR01JcnFVMHorcktKRTNmQ05zdTJVCnhOd0FYcjBTUTVDU08vUlBKTEticHIwVHpDblpPNlp6ZlZXd0VrSnZPYU5FQm9CY3hQWDRaSC9kZDJra1MxSDAKaXl6NlNLTytROE05MHVSYkVyWkljQ29BOTVDaUpHSXRVZ0pqWlhBSmh3S0JnRFhwMmF0c2FPSVRpM0lRcWxsQwpsL00xREhOOFBZNWVIRllpVk0wZSs5b2J5eHVwOUpVL0hUM215R1J4V2lWT0dCa0h6ciswS05QeE9Ub2xucHlLCkFvWEYydjdwTVAyU3hTMDRnL0o1NnozV0RWNDZDRDh3cGJOT3J3SW93ZUhlY1Y2RkRlSWY1clBJVzhIZmRua0MKR2sycFlnSlVDRzdPT01vR1dZMkh6di8xCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0=";
char * der_crt;
char * der_key;
char * pem_crt;
char * pem_key;
long length;

int main(int argc, char** argv) {	
	CryptStringToBinary(base64_crt, strlen(base64_crt), CRYPT_STRING_BASE64, 0, &length, 0, 0);
	pem_crt = malloc(sizeof(char) * length);
	CryptStringToBinary(base64_crt, strlen(base64_crt), CRYPT_STRING_BASE64, pem_crt, &length, 0, 0);
	printf("%i\n%s\n\n", length, pem_crt);

	CryptStringToBinary(pem_crt, strlen(pem_crt), CRYPT_STRING_BASE64HEADER, 0, &length, 0, 0);
	der_crt = malloc(sizeof(char) * length);
	CryptStringToBinary(pem_crt, strlen(pem_crt), CRYPT_STRING_BASE64HEADER, der_crt, &length, 0, 0);
	printf("%i\n%s\n\n", length, der_crt);

	CryptStringToBinary(base64_key, strlen(base64_key), CRYPT_STRING_BASE64, 0, &length, 0, 0);
	pem_key = malloc(sizeof(char) * length);
	CryptStringToBinary(base64_key, strlen(base64_key), CRYPT_STRING_BASE64, pem_key, &length, 0, 0);
	printf("%i\n%s\n\n", length, pem_key);

	CryptStringToBinary(pem_key, strlen(pem_key), CRYPT_STRING_BASE64HEADER, 0, &length, 0, 0);
	der_key = malloc(sizeof(char) * length);
	CryptStringToBinary(pem_key, strlen(pem_key), CRYPT_STRING_BASE64HEADER, der_key, &length, 0, 0);
	printf("%i\n%s\n\n", length, der_key);

	free(pem_crt);
	free(der_crt);
	free(der_key);
	free(pem_key);

	return 0;
}



#include "../log.h"
#include "http.h"

typedef struct http_certificate_string {
    char * private;
    char * public;
} HTTP_CERTIFICATE_STRING, *PHTTP_CERTIFICATE_STRING;

int http_certificate_initialize_new(struct http_instance * const inst, struct http_blob * const public, struct http_blob * const private) {
    BCRYPT_ALG_HANDLE algorithm;
    NTSTATUS status;    
    BCRYPT_KEY_HANDLE pubkey;
    BCRYPT_KEY_HANDLE prvkey;

    status = BCryptOpenAlgorithmProvider(&algorithm, "RSA", NULL, 0);
    if (BCRYPT_SUCCESS(status) == FALSE) {
        return 0;
    }

    /* How do you pair public and private keys... */
    status = BCryptImportKeyPair(algorithm, NULL, BCRYPT_RSAPUBLIC_BLOB, &pubkey, public->data, public->length, 0);
    if (BCRYPT_SUCCESS(status) == FALSE) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return 0;
    }

    status = BCryptImportKey(algorithm, NULL, BCRYPT_RSAPRIVATE_BLOB, &prvkey, private->data, private->length, 0);
    if (BCRYPT_SUCCESS(status) == FALSE) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        BCryptFreeBuffer(pubkey);
        return 0;
    }

    status = BCryptFinalizeKeyPair(pubkey, 0);
    if (BCRYPT_SUCCESS(status) == FALSE) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        BCryptFreeBuffer(pubkey);
        BCryptFreeBuffer(prvkey);
        return 0;
    }
    status = BCryptFinalizeKeyPair(prvkey, 0);
    if (BCRYPT_SUCCESS(status) == FALSE) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        BCryptFreeBuffer(pubkey);
        BCryptFreeBuffer(prvkey);
        return 0;
    }

    status = BCryptCloseAlgorithmProvider(&algorithm, 0);
    if (BCRYPT_SUCCESS(status) == FALSE) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        BCryptFreeBuffer(pubkey);
        BCryptFreeBuffer(prvkey);
        return 0;
    }
    
    CertCreateSelfSignCertificate(key, )

        certContext = CertCreateSelfSignCertificate(keyHandle, &nameBlob, 0, &keyProvInfo, nullptr,
        nullptr, nullptr, &certExtensions);
    if (!certContext)
        goto fail;
    certStore = CertOpenSystemStoreW(NULL, L"MY");
    if (!certStore)
        goto fail;
    if (!CertAddCertificateContextToStore(certStore, certContext, CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
        goto fail;
    result = true;

    BCryptCloseAlgorithmProvider(algorithm, 0);
}

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
    auth.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
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


#include "../log.h"
#include "http.h"
#include <signal.h>
int http_server_initialize(struct http_instance * const inst) {
    int result = 0;
    ADDRINFO hint;
    ADDRINFO *addr;
    WSADATA data;

    result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        return 0;
    }

    hint.ai_addr      = 0;
    hint.ai_addrlen   = 0;
    hint.ai_canonname = 0;
    hint.ai_family    = AF_UNSPEC;
    hint.ai_flags     = AF_UNSPEC;
    hint.ai_next      = 0;
    hint.ai_protocol  = IPPROTO_TCP;
    hint.ai_socktype  = SOCK_STREAM;


    result = getaddrinfo(inst->address, inst->port, &hint, &addr);
    if (result != 0) {
        return 0;
    }

    inst->listener = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (inst->listener == INVALID_SOCKET) {
        freeaddrinfo(addr);
        return 0;
    }

    result = bind(inst->listener, addr->ai_addr, addr->ai_addrlen);
    if (result != 0) {
        freeaddrinfo(addr);
        closesocket(inst->listener);
        return 0;
    }
    
    freeaddrinfo(addr);
    return 1;
}

int http_server_listen(struct http_instance * const inst) {
    int result = 0;
    
    if (inst == NULL || 
        inst->queue > SOMAXCONN || 
        inst->queue < 0) {
        return 0;
    }

    result = listen(inst->listener, inst->queue);

    if (result != 0) {
        return 0;
    }

    return 1;
}

int http_server_accept(struct http_instance * const inst) {
    if (inst == NULL ||
        inst->listener == INVALID_SOCKET) {
        return 0;
    }

    inst->reciever = accept(inst->listener, NULL, NULL);

    if (inst->reciever == INVALID_SOCKET) {
        return 0;
    }

    return 1;
}

int http_server_authenticate(struct http_instance * const inst) {
    PCtxtHandle   context = NULL;
    CHAR         *description_in_token[SO_MAX_MSG_SIZE];
    SecBuffer     description_in_buffers[2];
    SecBufferDesc description_in;
    SecBuffer     description_out_buffers[3];
    SecBufferDesc description_out;
    unsigned long attributes;
    TimeStamp     lifetime;
    long          result;
    long          sent;
    BOOL          authorized = FALSE;
    BOOL          first = TRUE;
    long          read = 0;

    if (inst == NULL ||
        inst->credentials == NULL ||
        inst->reciever == INVALID_SOCKET) {
        return 0;
    }

    description_in_buffers[0].BufferType = SECBUFFER_TOKEN;
    description_in_buffers[0].cbBuffer = SO_MAX_MSG_SIZE;
    description_in_buffers[0].pvBuffer = description_in_token;
    description_in_buffers[1].BufferType = SECBUFFER_EMPTY;
    description_in_buffers[1].cbBuffer = 0;
    description_in_buffers[1].pvBuffer = 0;
    description_in.cBuffers = 2;
    description_in.pBuffers = description_in_buffers;
    description_in.ulVersion = SECBUFFER_VERSION;

    description_out_buffers[0].BufferType = SECBUFFER_TOKEN;
    description_out_buffers[0].cbBuffer = 0;
    description_out_buffers[0].pvBuffer = 0;
    description_out.cBuffers = 1;
    description_out.pBuffers = description_out_buffers;
    description_out.ulVersion = SECBUFFER_VERSION;
    
    while (authorized == FALSE) {
        description_in.pBuffers[0].cbBuffer = recv(inst->reciever, description_in.pBuffers[0].pvBuffer, SO_MAX_MSG_SIZE, 0);
        if (description_in.pBuffers[0].cbBuffer == 0) {
            // No bytes read
        }

        result = AcceptSecurityContext(&inst->credentials->handle, context, &description_in, ASC_REQ_ALLOCATE_MEMORY, 0, context, &description_out, &attributes, &lifetime);
        printf("0x%x\n", result);

        if (result == SEC_E_OK ||
            result == SEC_I_COMPLETE_NEEDED) {
            authorized = TRUE;
        }

        if (result == SEC_I_COMPLETE_NEEDED ||
            result == SEC_I_COMPLETE_AND_CONTINUE) {

            result = CompleteAuthToken(context, &description_out);
                
            if (result < 0) {
                return 0;
            }
        }
            
        if (description_out_buffers[0].cbBuffer != 0 &&
            description_out_buffers[0].pvBuffer != 0) {
            send(inst->reciever, description_out_buffers[0].cbBuffer, sizeof(description_out_buffers[0].cbBuffer), 0);
            send(inst->reciever, description_out_buffers[0].pvBuffer, description_out_buffers[0].cbBuffer, 0);
        }
   }

   printf("Authentication successful\n");

    return 1;
}


/* Working keys i found online used for testing */
const char * const base64_crt = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUQxRENDQXJ5Z0F3SUJBZ0lFZE5jN2NEQU5CZ2txaGtpRzl3MEJBUXNGQURDQmdqRUxNQWtHQTFVRUJoTUMKVkZJeEd6QVpCZ05WQkFNTUVuZDNkeTVuY205M2RHOXdhV0V4TG1OdmJURUxNQWtHQTFVRUNBd0NXRmd4Q3pBSgpCZ05WQkFjTUFuaDRNUkl3RUFZRFZRUUtEQWxJWlhsVGRYSm1aWEl4S0RBbUJna3Foa2lHOXcwQkNRRVdHV2hsCmVYTjFjbVpsY25OQWNISnZkRzl1YldGcGJDNWpiMjB3SGhjTk1qTXdNek13TVRrek9EUXdXaGNOTXpNd016STMKTVRrek9EUXdXakNCZ2pFTE1Ba0dBMVVFQmhNQ1ZGSXhHekFaQmdOVkJBTU1FbmQzZHk1bmNtOTNkRzl3YVdFeApMbU52YlRFTE1Ba0dBMVVFQ0F3Q1dGZ3hDekFKQmdOVkJBY01Bbmg0TVJJd0VBWURWUVFLREFsSVpYbFRkWEptClpYSXhLREFtQmdrcWhraUc5dzBCQ1FFV0dXaGxlWE4xY21abGNuTkFjSEp2ZEc5dWJXRnBiQzVqYjIwd2dnRWkKTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEQlA1azBaSitkajQwL2ZGZ1pXYUV3bGx2egpNL3JTYjFNbnVvS2ZuOXQ0aDdlQXJpcVQ4dHhGak9WU05kSE0vNXQ2eTRqb1pyZFJkczMzZnArZGY0eVdaSEJXCmhhUFM2TTFDcU16a092WEpxbXAvQTNwNzFIOHdmRk1hMUo2VC96cjJta0hrZ2ZtckFQaktMV2FFWUovUHJRVVkKdnZpTW5YcTRkVEFyTGNVMnFOcHBmUHNYeWhMR21NTEpEdTlucjV5NDI4YXZHN2xJYlpzdGZVODUxT1FEVDhYTgpOaFp4aC9JTVVaQkpTRjcxVFV1UXBuQzVmSlJ4eTFCZkFrWUZpMWY1MEtsVFVlRW1hMkRva0U1cVB6TWllelZtCmdHWXNMSFFjSXR3aXU1YlRoNHJpdStVVHRMTmNKUjcvcWhLVkxXOCt5MFJVSUdwRG1LdGdzMEszNUZickFnTUIKQUFHalVEQk9NQjBHQTFVZERnUVdCQlQ5QUh5VVVpVThvYzRCTEQ2aTUraUxTdWVkempBZkJnTlZIU01FR0RBVwpnQlQ5QUh5VVVpVThvYzRCTEQ2aTUraUxTdWVkempBTUJnTlZIUk1FQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCCkN3VUFBNElCQVFCZXdhMGNWb1VlTHZwWisySktCaC9mR3g5cXRnRFJsYkNPTGg0ZFAxQU9MYTZwaUhZUXQxUFcKRGZaUWZwYXBsZUtVOVRjbVYxMHZNeHNBVmQrSWJ2NXdwS0Rnd1NHV1dleDFuYzhsTDNKZW5xaC9HODg4QVBxegpBbWtTd2R0dk1lUUY0TnVaZndZZDZKWmpzbE9WNVJaSW1oRmFTOWI3b21XYUZXQUdtbjR5Skd3MGdNYUE3TEs3CkhzQmwwdGc2ZG9qNHdYSEkwMWJ1enpibEpuVlBPSzZDZkxyZGVxOWFRT3pqYlBoN003dDZMaEZocmVCZnJIeFAKN3FjQUhhR25GbFg0bm9FYzlIbUtaYTJYL3N1NFVYWTRiYkZWVE1OSytzbmJwR29aNitmRDN3dHhiMVZXY3k1bAplRnJmSjBINUlud0lRQU1ITUZBOTRVcnFBU1U5WkpCOAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t";
const char * const base64_key = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRREJQNWswWkorZGo0MC8KZkZnWldhRXdsbHZ6TS9yU2IxTW51b0tmbjl0NGg3ZUFyaXFUOHR4RmpPVlNOZEhNLzV0Nnk0am9acmRSZHMzMwpmcCtkZjR5V1pIQldoYVBTNk0xQ3FNemtPdlhKcW1wL0EzcDcxSDh3ZkZNYTFKNlQvenIybWtIa2dmbXJBUGpLCkxXYUVZSi9QclFVWXZ2aU1uWHE0ZFRBckxjVTJxTnBwZlBzWHloTEdtTUxKRHU5bnI1eTQyOGF2RzdsSWJac3QKZlU4NTFPUURUOFhOTmhaeGgvSU1VWkJKU0Y3MVRVdVFwbkM1ZkpSeHkxQmZBa1lGaTFmNTBLbFRVZUVtYTJEbwprRTVxUHpNaWV6Vm1nR1lzTEhRY0l0d2l1NWJUaDRyaXUrVVR0TE5jSlI3L3FoS1ZMVzgreTBSVUlHcERtS3RnCnMwSzM1RmJyQWdNQkFBRUNnZ0VBTDhvWmloSmtRcU93YTRYRmg2ZFpyRmxTcmVjcDNRWjR5dmRkdkRuZEhZWjYKZzlFT2FINERxUk41MW9YR3QycHl1Y0JCd0M4K29GKy8rYmVQbzNSYWdRcWZtVlg5T0hnbjRwYzU3Q3NFZzNXbwpWbmEyd0k3QlVXMDlaQUkyb1NUYUlRZnV5YUsyNm1vWUhHOXp6Y0xUWXBsSURHR1Z0N2h1RTlXdkxzNW4yZWNqCngxUzJEVWg1eDJ2NmRNRVdueG5nckxqZC9ZN0xYaFV0am8zbHh0dE56S0tLaGZmNUFYcmFwWGNjOVdoK2tLa3gKZ3d1cW1OM2xucDg1UVkvTnJFWkY1WmlzajVYbjM5WkFqaGxTaS95NmxlSHFpdmJicXVreTlqREtwNTdVZVVlVApBWEJPZ2xIWEZySXlrVUl3cFZKbGVuVnhsRFQ3QXFCdmVndHZtR2hPQVFLQmdRRHErSU1jUmR3WlU4cEtvNy8zCjVJdXlJZk82V3FHemZ1WnBDejB0NnVIcDNHYVQ2TnQ4N3dZNkxRZ0E2Yk1Uc0FuUDBrS2E2THRxRHdQSW55RHcKcXFZZTkzOXRNWEJrdzBsdlQzc3NIK0JYclhNR0ZFOVl0WkpzUWdIK3R2eWV5ck5pTCs1THdmSDgrZXJ3YVNxRwpYeWNCZXlGSXFoZ1NqbEE4OUFxdTIxWGxBUUtCZ1FEU2l5eGM3cnVGcXdMaGxmeHBzaXY5MGJCenVMZ2QwSGcyCkltS3ZqVk1waWpaMjlWT09JVGs2NUZ5T05rbEZINlJuR0ZQYkRSb1dYVlVYdnZxYVRVTzl1ZUtobllHRkpGL2YKVFJOcTloeTZSdEpnejRvZFB5MUhtTjFiVmxYUTJBRHZaRU1pbHVTQ044KzdJVnlQMWdDeXR1OFdvZ1B1cEVlZgp4enRyYVZBZjZ3S0JnUURWTkUxek9BaHdpdEVCVFBnQkxNVjlDc1dta0ZvdERyWnZGaDJiTG9keXRlUDF6ZEpxCjJFL2tOYndQWi81dm5Nb3FZblRCTHUvdldsUnFrOGxGMXZJSkl6WGlsSHVSVW9tdGtJY0pFSnQxc3hLdHIzd1gKMkJsV1ZjYU5vdWd5QldjamJxNWcyMGlCN1JzNnJaSkNmdEJiemFmejBUTXFreXRIUTREMkRGc3lBUUtCZ1FDOQoyUjdrb2FSWDhJOUZpUEExQXFNbVdXbEp2OXZOam9pSEQ5UjZ4ZTJpUEczR01JcnFVMHorcktKRTNmQ05zdTJVCnhOd0FYcjBTUTVDU08vUlBKTEticHIwVHpDblpPNlp6ZlZXd0VrSnZPYU5FQm9CY3hQWDRaSC9kZDJra1MxSDAKaXl6NlNLTytROE05MHVSYkVyWkljQ29BOTVDaUpHSXRVZ0pqWlhBSmh3S0JnRFhwMmF0c2FPSVRpM0lRcWxsQwpsL00xREhOOFBZNWVIRllpVk0wZSs5b2J5eHVwOUpVL0hUM215R1J4V2lWT0dCa0h6ciswS05QeE9Ub2xucHlLCkFvWEYydjdwTVAyU3hTMDRnL0o1NnozV0RWNDZDRDh3cGJOT3J3SW93ZUhlY1Y2RkRlSWY1clBJVzhIZmRua0MKR2sycFlnSlVDRzdPT01vR1dZMkh6di8xCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0=";

/*
char * der_crt;
char * der_key;
char * pem_crt;
char * pem_key;
long length;
long result;
PCCERT_CONTEXT crt_context;
PCCERT_CONTEXT key_context;

int main(int argc, char** argv) {
	WSADATA data;
    result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        printf("%i\n", WSAGetLastError());
        return 1;
    }

	CryptStringToBinary(base64_crt, strlen(base64_crt), CRYPT_STRING_BASE64, 0, &length, 0, 0);
	pem_crt = malloc(sizeof(char) * length);
	CryptStringToBinary(base64_crt, strlen(base64_crt), CRYPT_STRING_BASE64, pem_crt, &length, 0, 0);

	CryptStringToBinary(pem_crt, strlen(pem_crt), CRYPT_STRING_BASE64HEADER, 0, &length, 0, 0);
	der_crt = malloc(sizeof(char) * length);
	CryptStringToBinary(pem_crt, strlen(pem_crt), CRYPT_STRING_BASE64HEADER, der_crt, &length, 0, 0);

	crt_context = CertCreateCertificateContext(X509_ASN_ENCODING, der_crt, length);
	if (crt_context == NULL) {
		printf("crt_context == NULL\n");
	}

	printf("%s\n\n", pem_crt);

	CryptStringToBinary(base64_key, strlen(base64_key), CRYPT_STRING_BASE64, 0, &length, 0, 0);
	pem_key = malloc(sizeof(char) * length);
	CryptStringToBinary(base64_key, strlen(base64_key), CRYPT_STRING_BASE64, pem_key, &length, 0, 0);

	printf("%s\n\n", pem_key);
	CryptStringToBinary(pem_key, strlen(pem_key), CRYPT_STRING_BASE64HEADER, 0, &length, 0, 0);
	der_key = malloc(sizeof(char) * length);
	CryptStringToBinary(pem_key, strlen(pem_key), CRYPT_STRING_BASE64HEADER, der_key, &length, 0, 0);

	CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, der_key, length, 0, 0, 0, 0);

	key_context = CertCreateCertificateContext(PKCS_7_ASN_ENCODING, der_key, length);
	if (key_context == NULL) {
		printf("key_context == NULL\n");
	}

	free(pem_crt);
	free(der_crt);
	free(der_key);
	free(pem_key);

	return 0;
}
*/

/* Log Template: "[%i:%s]: %s", __LINE__, __FILE__ */



$params = @{
    Subject = 'CN=www.growtopia1.com,O=FenrirBots'
    DnsName = 'www.growtopia1.com', 'www.growtopia2.com', '127.0.0.1'
    CertStoreLocation = 'Cert:\LocalMachine\My'
    KeyAlgorithm = 'RSA'
    KeyLength = 2048
}
New-SelfSignedCertificate @params