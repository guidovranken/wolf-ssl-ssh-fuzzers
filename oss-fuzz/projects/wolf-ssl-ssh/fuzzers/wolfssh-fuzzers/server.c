#define WOLFSSH_SCP
#include <wolfssh/ssh.h>
#include <wolfssh/wolfscp.h>
#include <fuzzers/shared.h>

WOLFSSH_CTX* ctx = NULL;

static const char serverBanner[] = "wolfSSH Example Server\n";

static int wsUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    /* TODO */
    return WOLFSSH_USERAUTH_SUCCESS;
    //return WOLFSSH_USERAUTH_FAILURE;
}

int fuzzerScpRecvCallback(WOLFSSH* ssh, int state, const char* basePath,
        const char* fileName, int fileMode, word64 mTime, word64 aTime,
        word32 totalFileSz, byte* buf, word32 bufSz, word32 fileOffset,
        void* ctx) {
    if ( basePath ) /* noret */ memory_test(basePath, strlen(basePath));
    if ( fileName ) /* noret */ memory_test(fileName, strlen(fileName));

    switch ( state ) {
        case WOLFSSH_SCP_NEW_REQUEST:
            return WS_SCP_CONTINUE;
        case WOLFSSH_SCP_NEW_FILE:
            return WS_SCP_CONTINUE;
        case WOLFSSH_SCP_FILE_PART:
            /* noret */ memory_test(buf, bufSz);
            return WS_SCP_CONTINUE;
        case WOLFSSH_SCP_FILE_DONE:
        case WOLFSSH_SCP_NEW_DIR:
        case WOLFSSH_SCP_END_DIR:
            return WS_SCP_CONTINUE;
    }

    return WS_SCP_ABORT;
}

int fuzzerScpSendCallback(WOLFSSH* ssh, int state, const char* peerRequest,
        char* fileName, word32 fileNameSz, word64* mTime, word64* aTime,
        int* fileMode, word32 fileOffset, word32* totalFileSz, byte* buf,
        word32 bufSz, void* ctx) {

    if ( fileName ) memset(fileName, 0, fileNameSz);

    struct __attribute__((__packed__)) {
        word64 mTime;
        word64 aTime;
        int fileMode;
        word32 totalFileSz;
    } fileinfo;

    switch ( state ) {
        case WOLFSSH_SCP_NEW_REQUEST:
            return WS_SUCCESS;
        case WOLFSSH_SCP_SINGLE_FILE_REQUEST:
            if ( fileNameSz < 2 ) {
                return WS_SCP_ABORT;
            }

            fileName[0] = 'x';
            fileName[1] = 0;

            if ( fuzzer_data_size < sizeof(fileinfo) ) {
                return WS_SCP_ABORT;
            }

            memcpy(&fileinfo, fuzzer_data, sizeof(fileinfo));
            fuzzer_data += sizeof(fileinfo);
            fuzzer_data_size -= sizeof(fileinfo);

            const int maxReadSize = fileinfo.totalFileSz > bufSz ? bufSz : fileinfo.totalFileSz;
            const int numRead = fuzzer_recv(NULL, buf, maxReadSize, NULL);
            if ( numRead < 0 ) {
                return WS_SCP_ABORT;
            }

            *mTime = fileinfo.mTime;
            *aTime = fileinfo.aTime;
            *fileMode = fileinfo.fileMode;
            *totalFileSz = fileinfo.totalFileSz;

            return numRead;
        case WOLFSSH_SCP_RECURSIVE_REQUEST:
            {
                uint8_t b;
                if ( fuzzer_data_size < 1 ) {
                    return WS_SCP_ABORT;
                }

                b = *fuzzer_data;
                fuzzer_data += 1;
                fuzzer_data_size -= 1;

                switch ( b % 4 ) {
                    case    0:
                        return WS_SCP_EXIT_DIR;
                    case    1:
                        return WS_SCP_ENTER_DIR;
                    case    2:
                        return WS_SCP_EXIT_DIR_FINAL;
                    case    3:
                        return WS_SCP_ABORT;
                }
            }
        case WOLFSSH_SCP_CONTINUE_FILE_TRANSFER:
            memset(buf, 0, bufSz);
            return bufSz;
    }

    return WS_SCP_ABORT;
}

FUZZER_INITIALIZE_HEADER
{
    if (wolfSSH_Init() != WS_SUCCESS) {
        abort();
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if ( ctx == NULL ) {
        abort();
    }

    /* noret */ wolfSSH_SetUserAuth(ctx, wsUserAuth);

    if ( wolfSSH_CTX_SetBanner(ctx, serverBanner) != WS_SUCCESS ) {
        abort();
    }

    /* noret */ wolfSSH_SetIORecv(ctx, fuzzer_recv);
    /* noret */ wolfSSH_SetIOSend(ctx, fuzzer_send);

    /* noret */ wolfSSH_SetScpRecv(ctx, fuzzerScpRecvCallback);
    /* noret */ wolfSSH_SetScpSend(ctx, fuzzerScpSendCallback);
}
FUZZER_INITIALIZE_FOOTER_1
FUZZER_INITIALIZE_FOOTER_2

FUZZER_RUN_HEADER
{
    WOLFSSH* ssh = NULL;
    int ret;
    uint8_t buffer[512];

    fuzzer_set_data(data, size);
    ssh = wolfSSH_new(ctx);

    if ( (ret = wolfSSH_accept(ssh)) != WS_SUCCESS ) {
        goto end;
    }

    for (size_t i = 0; i < 5; i++) {
        ret = wolfSSH_stream_read(ssh, buffer, sizeof(buffer));
        if ( ret < 0 ) {
            break;
        }
        ret = wolfSSH_stream_send(ssh, buffer, ret);
        if ( ret < 0 ) {
            break;
        }
    }


end:
    ret = wolfSSH_shutdown(ssh);
    wolfSSH_free(ssh);
    fuzzer_unset_data();
}
FUZZER_RUN_FOOTER
