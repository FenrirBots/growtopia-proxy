#ifndef __HTTP_H_
#define __HTTP_H_
#include "http_type.h"

#define SECURITY_WIN32

/* Winsock */
#include <winsock2.h>
#include <ws2tcpip.h>

/* Secure Socket Protocol Interface */
#include <sspi.h>
#include <schannel.h>

typedef struct http_certificate {
    char *location;
    char *subject;
    char *issuer;
} HTTP_CERTIFICATE;

typedef struct http_blob {
    void *data;
    long  length;
} HTTP_BLOB;

typedef struct http_credentials {
    PCCERT_CONTEXT context;
    CREDHANDLE handle;
    TIMESTAMP expiry;
} HTTP_CREDENTIALS;

typedef struct http_instance {
    char *port;
    char *address;
    int   queue;

    SOCKET listener;
    SOCKET reciever;
    HTTP_CREDENTIALS *credentials;
} HTTP_INSTANCE;

int http_server_initialize(struct http_instance * const inst);
int http_server_listen(struct http_instance * const inst);
int http_server_accept(struct http_instance * const inst);
int http_server_authenticate(struct http_instance * const inst);
int http_certificate_initialize(struct http_instance * const inst, struct http_certificate * const cred);

#endif