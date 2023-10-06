#include "http.h"

int http_server_initialize(struct http_instance * const inst) {
    int result = 0;
    ADDRINFO hint;
    ADDRINFO *addr;
    WSADATA data;

    result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        DEBUG_LOG("failed to initialize winsock");
        return 1;
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
        DEBUG_LOG("failed to get address info");
        return 0;
    }

    inst->listener = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (inst->listener == INVALID_SOCKET) {
        DEBUG_LOG("failed to get the socket");
        freeaddrinfo(addr);
        return 0;
    }

    result = bind(inst->listener, addr->ai_addr, addr->ai_addrlen);
    if (result != 0) {
        DEBUG_LOG("failed to bind the socket");
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
        DEBUG_LOG("could not listen on socket");
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
        DEBUG_LOG("failed to accept the connection");
        return 0;
    }

    return 1;
}

int http_server_authenticate(struct http_instance * const inst) {
    PCtxtHandle   context = NULL;
    CHAR         *description_in_token[16384];
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

    if (inst == NULL ||
        inst->credentials == NULL ||
        inst->reciever == INVALID_SOCKET) {
        return 0;
    }

    description_in_buffers[0].BufferType = SECBUFFER_TOKEN;
    description_in_buffers[0].cbBuffer = 16384;
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
    description_out_buffers[1].BufferType = SECBUFFER_ALERT;
    description_out_buffers[1].cbBuffer = 0;
    description_out_buffers[1].pvBuffer = 0;
    description_out_buffers[2].BufferType = SECBUFFER_EMPTY;
    description_out_buffers[2].cbBuffer = 0;
    description_out_buffers[2].pvBuffer = 0;
    description_out.cBuffers = 3;
    description_out.pBuffers = description_out_buffers;
    description_out.ulVersion = SECBUFFER_VERSION;
    
    while (authorized == FALSE) {
        result = recv(inst->reciever, description_in.pBuffers[0].pvBuffer, 16384, 0);
        if (result == 0) {
            return 0;
        }

        printf("0x%x", result);

        result = AcceptSecurityContext(&inst->credentials->handle, NULL, &description_in, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR, 0, context, &description_out, &attributes, &lifetime);

        if (result == SEC_I_COMPLETE_AND_CONTINUE ||
             result == SEC_I_COMPLETE_NEEDED ||
             result == SEC_I_CONTINUE_NEEDED || 
             result == SEC_E_OK)
        {
            if (result == SEC_I_COMPLETE_AND_CONTINUE) {
                DEBUG_LOG("SEC_I_COMPLETE_AND_CONTUNUE");
                CompleteAuthToken(context, &description_out);
            }
            if (result == SEC_I_COMPLETE_NEEDED) {
                DEBUG_LOG("SEC_I_COMPLETE_NEEDED");
            }
            if (result == SEC_I_CONTINUE_NEEDED) {
                DEBUG_LOG("SEC_I_CONTINUE_NEEDED");
            }
            if (result == SEC_E_OK) {
                DEBUG_LOG("SEC_E_OK");
            }
            
            if (description_out_buffers[0].cbBuffer != 0 &&
                description_out_buffers[0].pvBuffer != 0) {
                sent = send(inst->reciever, (const char*)description_out_buffers[0].pvBuffer, description_out_buffers[0].cbBuffer, 0);
                if (sent != description_out_buffers[0].cbBuffer) {
                    DEBUG_LOG("Incorrect amount of bytes sent");
                    return 0;
                }
            }
            
            if (result == SEC_E_OK) {
                authorized = TRUE;
            }
        } else if(result == SEC_E_INCOMPLETE_MESSAGE) {
            /* Do nothing, we do not have enough of the packet to continue */
        } else {
            DEBUG_LOG("Unknown error");
            printf("0x%x\n", result);
            return 0;
        }
    }

    return 1;
}