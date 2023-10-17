#include "../log.h"
#include "http.h"
#include <tchar.h>
int http_server_initialize(struct http_instance * const inst) {
    int result = 0;
    ADDRINFO hint;
    ADDRINFO *addr;
    WSADATA data;

    result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        printf("[%s:%llu]: WSAStartup error (0x%x)\n", __LINE__, __FILE__, result);
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
        printf("[%s:%llu]: An error occoured while getting the address information (0x%x)\n", __LINE__, __FILE__, WSAGetLastError());
        return 0;
    }

    inst->listener = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (inst->listener == INVALID_SOCKET) {
        printf("[%s:%llu]: An error occoured while creating the socket (0x%x)\n", __LINE__, __FILE__, WSAGetLastError());
        freeaddrinfo(addr);
        return 0;
    }

    /* This will throw an ACCESS_VIOLATION if the requested port is in use, this needs to be fixed */
    result = bind(inst->listener, addr->ai_addr, addr->ai_addrlen);
    if (result != 0) {
        printf("[%s:%llu]: An error occoured while binding the port (0x%x)\n", __LINE__, __FILE__, WSAGetLastError());
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
    CHAR         *description_in_token;
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
    
    while (authorized == FALSE) {
        description_in_token = malloc(sizeof(CHAR) * SO_MAX_MSG_SIZE);
        
        // description_in_token = description_in_token + sent;
        result = recv(inst->reciever, description_in_token + sent, SO_MAX_MSG_SIZE - sent, 0);
        if (result <= 0 ||
            result + sent > SO_MAX_MSG_SIZE) {
            printf("An error occoured while reciving data\n");
            return 0;
        }

        sent = sent + result;

        description_in_buffers[0].BufferType = SECBUFFER_TOKEN;
        description_in_buffers[0].cbBuffer = sent;
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
        description_out_buffers[0].BufferType = SECBUFFER_ALERT;
        description_out_buffers[0].cbBuffer = 0;
        description_out_buffers[0].pvBuffer = 0;
        description_out_buffers[0].BufferType = SECBUFFER_EMPTY;
        description_out_buffers[0].cbBuffer = 0;
        description_out_buffers[0].pvBuffer = 0;
        description_out.cBuffers = 3;
        description_out.pBuffers = description_out_buffers;
        description_out.ulVersion = SECBUFFER_VERSION;

        result = AcceptSecurityContext(
            &inst->credentials->handle, 
            context, 
            &description_in, 
            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_STREAM, 
            0, 
            context, 
            &description_out, 
            &attributes, 
            &lifetime);
        printf("0x%x\n", result);
        
        /* Testing copy from here */
        /* https://github.com/gabriel-sztejnworcel/schannel-tls-cpp/blob/b3da6aab55f33f75d07e6fb791e6090626d1df8b/schannel-tls-cpp/schannel-helper.cpp#L275 */
        /* 0x80090326 SEC_E_ILLEGAL_MESSAGE */
        /* 0x80090318 SEC_I_INCOMPLETE_MESSAGE */
        switch (result) {
            case SEC_E_OK:
            case SEC_I_CONTINUE_NEEDED:
                if (description_out_buffers[0].cbBuffer != 0 &&
                    description_out_buffers[0].pvBuffer != 0) {
                    send(inst->reciever, (const char*)description_out_buffers[0].pvBuffer, description_out_buffers[0].cbBuffer, 0);
                }

                if (result == SEC_E_OK) {
                    authorized = TRUE;
                }
            break;

            case SEC_I_COMPLETE_AND_CONTINUE:
            case SEC_I_COMPLETE_NEEDED:
                if (CompleteAuthToken(context, &description_out) != SEC_E_OK) {
                    printf("Authentication failed\n");
                    return 0;
                }

                if (description_out_buffers[0].cbBuffer != 0 &&
                    description_out_buffers[0].pvBuffer != 0) {
                    send(inst->reciever, (const char*)description_out_buffers[0].pvBuffer, description_out_buffers[0].cbBuffer, 0);
                }

                if (result == SEC_I_COMPLETE_NEEDED) {
                    authorized = TRUE;
                }
            break;

            default:
                /* Currently throwing 0x57 (ERROR_INVALID_PARAMETER) after the 3rd iteration */
                free(description_in_token);
                printf("Unknown Error [0x%x](0x%x)\n", GetLastError(), result);
                return 0;
        }

/*
        if (result == SEC_E_OK ||
            result == SEC_I_COMPLETE_AND_CONTINUE ||
            result == SEC_I_COMPLETE_NEEDED ||
            result == SEC_I_CONTINUE_NEEDED) {
            if (result == SEC_E_OK ||
                result == SEC_I_COMPLETE_AND_CONTINUE) {
                result = CompleteAuthToken(context, &description_out);

                if (result != SEC_E_OK) {
                    return 0;
                }

                authorized = TRUE;
            }

            if (description_out_buffers[0].cbBuffer != 0 &&
                description_out_buffers[0].pvBuffer != 0) {
                send(inst->reciever, (const char*)description_out_buffers[0].pvBuffer, description_out_buffers[0].cbBuffer, 0);
            }
        }
*/
    }

    
//     while (authorized == FALSE) {
//         result = recv(inst->reciever, description_in.pBuffers[0].pvBuffer, SO_MAX_MSG_SIZE, 0);
//         printf("Bytes Recieved: %i\n", result);

//         if (result == 0) {
//             return 0;
//         }

//         result = AcceptSecurityContext(&inst->credentials->handle, context, &description_in, ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR, SECURITY_NATIVE_DREP, context, &description_out, &attributes, &lifetime);

//         if (result == SEC_E_OK) {
//             authorized = TRUE;
//         }

//         if (result == SEC_I_COMPLETE_NEEDED ||
//             result == SEC_I_COMPLETE_AND_CONTINUE) {
//             result = CompleteAuthToken(context, &description_out);
                
//             if (result < 0) {
//                 return 0;
//             }
//         }
            
//         if (description_out_buffers[0].cbBuffer != 0 &&
//             description_out_buffers[0].pvBuffer != 0) {
//             sent = send(inst->reciever, (const char*)description_out_buffers[0].pvBuffer, description_out_buffers[0].cbBuffer, 0);
//             if (sent != description_out_buffers[0].cbBuffer) {
//                 return 0;
//             }
//         }
//    }

   printf("Authentication successful\n");

    return 1;
}