#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <fuzzers/shared.h>

FUZZER_INITIALIZE_HEADER
FUZZER_INITIALIZE_FOOTER_1
FUZZER_INITIALIZE_FOOTER_2

FUZZER_RUN_HEADER
{
    DecodedCRL dcrl;
    InitDecodedCRL(&dcrl, NULL);
    ParseCRL(&dcrl, data, size, NULL);
    FreeDecodedCRL(&dcrl);
}
FUZZER_RUN_FOOTER
