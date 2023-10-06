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

#define DEBUG
#if defined(DEBUG)
#include <stdio.h>
#define DEBUG_LOG(T) printf("[%i:%s()]: %s\n", __LINE__, __FUNCTION__, T)
#else
#define DEBUG_LOG(T)
#endif

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

typedef struct http_certificate {
    char *name;
    char *location;
    char *issuer;
} HTTP_CERTIFICATE;

typedef struct http_certificate_file {
    char *location;
} HTTP_CERTIFICATE_FILE;

typedef struct http_certificate_resource {
    long public;
    long private;
} HTTP_CERTIFICATE_RESOURCE;

typedef struct http_blob {
    void *data;
    long  length;
} HTTP_BLOB;

#endif