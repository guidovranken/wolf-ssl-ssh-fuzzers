#include <stdint.h>
#include <stdlib.h>
extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
}
#include <fuzzing/datasource/datasource.hpp>

WC_RNG      rng;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    wc_InitRng(&rng);

    return 0;
}

static bool PKCS7_Verify(uint8_t* cert, size_t cert_size, uint8_t* data, size_t data_size) {
    bool ret = false;

    PKCS7* pkcs7 = wc_PKCS7_New(NULL, -1);

    if ( wc_PKCS7_InitWithCert(pkcs7, cert, cert_size) == 0 ) {
        if ( wc_PKCS7_VerifySignedData(pkcs7, data, data_size) == 0 ) {
            ret = true;
        }

    }

    wc_PKCS7_Free(pkcs7);

    return ret;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    auto ds = fuzzing::datasource::Datasource(data, size);

    try {
        switch ( ds.Get<uint8_t>() ) {
            case    0:
                {
                    auto cert = ds.GetData(0);
                    auto data = ds.GetData(0);

                    PKCS7* pkcs7 = wc_PKCS7_New(NULL, -1);
                    if ( wc_PKCS7_InitWithCert(pkcs7, cert.data(), cert.size()) == 0 ) {
                        wc_PKCS7_VerifySignedData(pkcs7, data.data(), data.size());
                    }
                    wc_PKCS7_Free(pkcs7);
                }
                break;
            case    1:
                {
                    auto cert = ds.GetData(0);
                    auto content = ds.GetData(0);
                    auto key = ds.GetData(0);
                    const auto outSz = ds.Get<uint16_t>();
                    std::vector<uint8_t> out(outSz);
                    const auto encryptOID = ds.Get<uint16_t>();
                    const auto hashOID = ds.Get<uint16_t>();

                    PKCS7* pkcs7 = wc_PKCS7_New(NULL, -1);
                    if ( wc_PKCS7_InitWithCert(pkcs7, cert.data(), cert.size()) == 0 ) {
                        pkcs7->content = content.data();
                        pkcs7->contentSz = content.size();
                        pkcs7->privateKey = key.data();
                        pkcs7->privateKeySz = key.size();
                        pkcs7->encryptOID = encryptOID;
                        pkcs7->hashOID = hashOID;
                        pkcs7->rng = &rng;
                        int ret;
                        if ( (ret = wc_PKCS7_EncodeSignedData(pkcs7, out.data(), outSz)) > 0 ) {
                            if ( PKCS7_Verify(cert.data(), cert.size(), out.data(), ret) == false ) {
#if 0 /* Enabled for debugging */
                                printf("Cert:\n");
                                for (size_t i = 0; i < cert.size(); i++) {
                                    printf("0x%02X, ", cert[i]);
                                }
                                printf("\n");

                                printf("Content:\n");
                                for (size_t i = 0; i < content.size(); i++) {
                                    printf("0x%02X, ", content[i]);
                                }
                                printf("\n");

                                printf("Key:\n");
                                for (size_t i = 0; i < key.size(); i++) {
                                    printf("0x%02X, ", key[i]);
                                }
                                printf("\n");
                                printf("encryptOID: %u\n", encryptOID);
                                printf("hashOID: %u\n", hashOID);
                                printf("outSz: %u\n", outSz);

                                printf("Failed to verify PKCS7 data\n");
                                abort();
#endif
                            }
                        }
                    }
                    wc_PKCS7_Free(pkcs7);
                }
                break;
        }
    } catch ( ... ) { }

    return 0;
}
