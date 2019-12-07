#!/bin/bash -eu

rm -rf $SRC/fuzzers/wolfssl/
mkdir -p $SRC/fuzzers/wolfssl/
cp -R $SRC/wolfssl/ $SRC/fuzzers/wolfssl/
cp -R $SRC/fuzzers/wolfssl-fuzzers $SRC/fuzzers/wolfssl/wolfssl/
cp -R $SRC/fuzzers/wolfssl/wolfssl/ $SRC/fuzzers/wolfssl/wolfssl_trace_pc_guard/

export CFLAGS="$CFLAGS -DWOLFSSL_STATIC_PSK"
export WOLFSSL_CONFIGURE_PARAMS="$WOLFSSL_BASE_CONFIGURE_PARAMS --enable-tls13 --enable-ocsp --enable-dtls --enable-sni --enable-blake2 --enable-blake2s --enable-curve25519 --enable-session-ticket --enable-nullcipher --enable-crl --enable-ed25519 --enable-psk --enable-earlydata --enable-postauth --enable-hrrcookie --enable-opensslextra --enable-certext --enable-tlsx --enable-oldtls --enable-tlsv10 --enable-indef --enable-psk"

# Build everything with -fsanitize=fuzzer-no-link (normal code coverage guided fuzzing)
    # Build wolfSSL
        cd $SRC/fuzzers/wolfssl/wolfssl/
        autoreconf -ivf
        ./configure $WOLFSSL_CONFIGURE_PARAMS
        make -j$(nproc)

    # Build wolfSSL fuzzers (code coverage guided)
        cd $SRC/fuzzers/wolfssl/wolfssl/wolfssl-fuzzers

        make -B fuzzer-misc
        make -B fuzzer-crl
        make -B fuzzer-ocsp
        make -B fuzzer-x509

        cp fuzzer-misc $OUT/fuzzer-wolfssl-misc
        cp fuzzer-crl $OUT/fuzzer-wolfssl-crl
        cp fuzzer-ocsp $OUT/fuzzer-wolfssl-ocsp
        cp fuzzer-x509 $OUT/fuzzer-wolfssl-x509

# Build everything with -fsanitize-coverage=trace-pc-guard (for intensity and allocation guided fuzzing)
    export CFLAGS=${CFLAGS/"-fsanitize=fuzzer-no-link"/"-fsanitize-coverage=trace-pc-guard"}
    # Build wolfSSL
        cd $SRC/fuzzers/wolfssl/wolfssl_trace_pc_guard/
        autoreconf -ivf
        ./configure $WOLFSSL_CONFIGURE_PARAMS
        make -j$(nproc)

    # Build wolfSSL fuzzers (intensity guided)
        cd $SRC/fuzzers/wolfssl/wolfssl_trace_pc_guard/wolfssl-fuzzers

        make -B fuzzer-misc-intensity
        make -B fuzzer-crl-intensity
        make -B fuzzer-ocsp-intensity
        make -B fuzzer-x509-intensity

        cp fuzzer-misc-intensity $OUT/fuzzer-wolfssl-misc-intensity
        cp fuzzer-crl-intensity $OUT/fuzzer-wolfssl-crl-intensity
        cp fuzzer-ocsp-intensity $OUT/fuzzer-wolfssl-ocsp-intensity
        cp fuzzer-x509-intensity $OUT/fuzzer-wolfssl-x509-intensity

    # Build wolfSSL fuzzers (allocation guided)
        cd $SRC/fuzzers/wolfssl/wolfssl_trace_pc_guard/wolfssl-fuzzers

        make -B fuzzer-misc-allocation
        make -B fuzzer-crl-allocation
        make -B fuzzer-ocsp-allocation
        make -B fuzzer-x509-allocation

        cp fuzzer-misc-allocation $OUT/fuzzer-wolfssl-misc-allocation
        cp fuzzer-crl-allocation $OUT/fuzzer-wolfssl-crl-allocation
        cp fuzzer-ocsp-allocation $OUT/fuzzer-wolfssl-ocsp-allocation
        cp fuzzer-x509-allocation $OUT/fuzzer-wolfssl-x509-allocation
