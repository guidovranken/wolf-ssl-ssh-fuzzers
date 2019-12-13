#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <fuzzers/shared.h>

#define NUM_METHODS 5

WOLFSSL_CTX* ctx[NUM_METHODS];
WOLFSSL_METHOD* method[NUM_METHODS];

static unsigned int psk_cb(WOLFSSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    memset(identity, 0, id_max_len);
    memset(key, 0, key_max_len);
    return key_max_len;
}

FUZZER_INITIALIZE_HEADER
{
    method[0] = wolfTLSv1_2_client_method();
    method[1] = wolfTLSv1_1_client_method();
    method[2] = wolfTLSv1_3_client_method();
    method[3] = wolfDTLSv1_2_client_method();
    method[4] = wolfTLSv1_client_method();

    for (int i = 0; i < NUM_METHODS; i++) {
        if ( (ctx[i] = wolfSSL_CTX_new(method[i])) == NULL) {
            abort();
        }

        wolfSSL_CTX_SetIORecv(ctx[i], fuzzer_recv);
        wolfSSL_CTX_SetIOSend(ctx[i], fuzzer_send);

        if ( wolfSSL_CTX_UseSessionTicket(ctx[i]) != WOLFSSL_SUCCESS ) {
            abort();
        }

        if (wolfSSL_CTX_set_cipher_list(ctx[i], "PSK-NULL-SHA256") != WOLFSSL_SUCCESS) {
            abort();
        }
        /* noret */ wolfSSL_CTX_set_psk_client_callback(ctx[i], psk_cb);
    }
}
FUZZER_INITIALIZE_FOOTER_1
FUZZER_INITIALIZE_FOOTER_2

FUZZER_RUN_HEADER
{
    if ( size < 1 ) {
        return 0;
    }

    unsigned char ctxIdx = data[size-1];
    size--;

    if ( ctxIdx >= NUM_METHODS ) {
        return 0;
    }
    if ( ctxIdx != 0 ) {
        return 0;
    }

    WOLFSSL* ssl;

    fuzzer_set_data(data, size);

    if ( (ssl = wolfSSL_new(ctx[ctxIdx])) == NULL) {
        goto end;
    }

    if ( wolfSSL_connect(ssl) == WOLFSSL_SUCCESS ) { }

end:
    /* noret */ wc_ClearErrorNodes();
    wolfSSL_free(ssl);

    fuzzer_unset_data();

}
FUZZER_RUN_FOOTER
