#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <fuzzers/shared.h>

FUZZER_INITIALIZE_HEADER
FUZZER_INITIALIZE_FOOTER_1
FUZZER_INITIALIZE_FOOTER_2

FUZZER_RUN_HEADER
{
    if ( size < 1 ) {
        return 0;
    }

    const uint8_t choice = *data;
    data++; size--;


    switch ( choice ) {
        case    0:
            {
                uint32_t outSz;

                if ( size < sizeof(outSz) ) {
                    return 0;
                }

                memcpy(&outSz, data, sizeof(outSz));
                data += sizeof(outSz); size -= sizeof(outSz);

                outSz &= 0xFFFFFF;

                uint8_t* out = malloc(outSz);
                if ( Base64_Decode(data, size, out, &outSz) == 0 ) {
                    memory_test(out, outSz);
                }
                free(out);
            }
            break;
        case    1:
            {
                uint32_t outSz;
                uint8_t mode;

                if ( size < sizeof(outSz) ) {
                    return 0;
                }

                memcpy(&outSz, data, sizeof(outSz));
                data += sizeof(outSz); size -= sizeof(outSz);

                outSz &= 0xFFFFFF;

                if ( size < sizeof(mode) ) {
                    return 0;
                }

                memcpy(&mode, data, sizeof(mode));
                data += sizeof(mode); size -= sizeof(mode);

                uint8_t* out = malloc(outSz);
                int ret = -1;
                switch ( mode % 3 ) {
                    case    0:
                        ret = Base64_Encode(data, size, out, &outSz);
                        break;
                    case    1:
                        ret = Base64_EncodeEsc(data, size, out, &outSz);
                        break;
                    case    2:
                        ret = Base64_Encode_NoNl(data, size, out, &outSz);
                        break;
                }
                if ( ret == 0 ) {
                    memory_test(out, outSz);
                }
                free(out);
            }
            break;
        case    2:
            {
                uint32_t outSz;

                if ( size < sizeof(outSz) ) {
                    return 0;
                }

                memcpy(&outSz, data, sizeof(outSz));
                data += sizeof(outSz); size -= sizeof(outSz);

                outSz &= 0xFFFFFF;

                uint8_t* out = malloc(outSz);
                if ( Base16_Decode(data, size, out, &outSz) == 0 ) {
                    memory_test(out, outSz);
                }
                free(out);
            }
            break;
        case    3:
            {
                uint32_t outSz;

                if ( size < sizeof(outSz) ) {
                    return 0;
                }

                memcpy(&outSz, data, sizeof(outSz));
                data += sizeof(outSz); size -= sizeof(outSz);

                outSz &= 0xFFFFFF;

                uint8_t* out = malloc(outSz);
                if ( Base16_Encode(data, size, out, &outSz) == 0 ) {
                    memory_test(out, outSz);
                }
                free(out);
            }
            break;
        case    4:
            {
                uint32_t outSz;

                if ( size < sizeof(outSz) ) {
                    return 0;
                }

                memcpy(&outSz, data, sizeof(outSz));
                data += sizeof(outSz); size -= sizeof(outSz);

                outSz &= 0xFFFFF;

                uint8_t* out = malloc(outSz);

                if ( wc_BerToDer(data, size, out, &outSz) == 0 ) {
                    memory_test(out, outSz);
                }

                free(out);
            }
            break;
    }
}
FUZZER_RUN_FOOTER
