#include <wolfssh/ssh.h>
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
}
FUZZER_INITIALIZE_FOOTER_1
FUZZER_INITIALIZE_FOOTER_2

FUZZER_RUN_HEADER
{
    WOLFSSH* ssh = NULL;
    int ret;

    fuzzer_set_data(data, size);
    ssh = wolfSSH_new(ctx);

    if ( (ret = wolfSSH_accept(ssh)) != WS_SUCCESS ) {
        goto end;
    }


end:
    ret = wolfSSH_shutdown(ssh);
    wolfSSH_free(ssh);
    fuzzer_unset_data();
}
FUZZER_RUN_FOOTER
