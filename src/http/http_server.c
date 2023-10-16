#include "../log.h"
#include "http.h"

int http_server_initialize(struct http_instance * const inst) {
    int result = 0;
    ADDRINFO hint;
    ADDRINFO *addr;
    WSADATA data;

    result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        printf("[%s:%llu]: WSAStartup error (0x%x)\n", __LINE__, __FILE__, WSAGetLastError());
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
        printf("[%s:%llu]: An error occoured while creating the socket (0x%x)\n", __LINE__, __FILE__, WSAGetLastError());
        return 0;
    }

    inst->listener = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (inst->listener == INVALID_SOCKET) {
        printf("[%s:%llu]: An error occoured while creating the socket (0x%x)\n", __LINE__, __FILE__, WSAGetLastError());
        freeaddrinfo(addr);
        return 0;
    }

    result = bind(inst->listener, addr->ai_addr, addr->ai_addrlen);
    if (result != 0) {
        printf("[%s:%llu]: An error occoured while creating the socket (0x%x)\n", __LINE__, __FILE__, WSAGetLastError());
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
    CHAR        **description_in_token;
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

    description_in_token = malloc(sizeof(CHAR) * SO_MAX_MSG_SIZE);
    while (authorized == FALSE) {
        description_in_token = description_in_token + sent;
    }

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
        result = recv(inst->reciever, description_in.pBuffers[0].pvBuffer, SO_MAX_MSG_SIZE, 0);
        printf("Bytes Recieved: %i\n", result);

        if (result == 0) {
            return 0;
        }

        result = AcceptSecurityContext(&inst->credentials->handle, context, &description_in, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR, SECURITY_NATIVE_DREP, context, &description_out, &attributes, &lifetime);
        printf("0x%x", result);

        if (result == SEC_E_OK) {
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
            sent = send(inst->reciever, (const char*)description_out_buffers[0].pvBuffer, description_out_buffers[0].cbBuffer, 0);
            if (sent != description_out_buffers[0].cbBuffer) {
                return 0;
            }
        }
   }

   printf("Authentication successful\n");

    return 1;
}