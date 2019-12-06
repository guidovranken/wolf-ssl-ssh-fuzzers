#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <fuzzers/shared.h>

FUZZER_INITIALIZE_HEADER
FUZZER_INITIALIZE_FOOTER_1
FUZZER_INITIALIZE_FOOTER_2

FUZZER_RUN_HEADER
{
    OcspResponse resp;
    CertStatus status;
    InitOcspResponse(&resp, &status, data, size);
    OcspResponseDecode(&resp, NULL, NULL, 1);
}
FUZZER_RUN_FOOTER
