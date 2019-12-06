#!/bin/bash -eu

rm -rf $SRC/fuzzers/wolfssl/
mkdir -p $SRC/fuzzers/wolfssl/
cp -R $SRC/wolfssl/ $SRC/fuzzers/wolfssl/
cp -R $SRC/fuzzers/wolfssl-fuzzers $SRC/fuzzers/wolfssl/wolfssl/

export CFLAGS="$CFLAGS -DWOLFSSL_STATIC_PSK"

# Build wolfSSL
    cd $SRC/fuzzers/wolfssl/wolfssl/
    autoreconf -ivf
    ./configure $WOLFSSL_BASE_CONFIGURE_PARAMS --enable-tls13 --enable-ocsp --enable-dtls --enable-sni --enable-blake2 --enable-blake2s --enable-curve25519 --enable-session-ticket --enable-nullcipher --enable-crl --enable-ed25519 --enable-psk --enable-earlydata --enable-postauth --enable-hrrcookie --enable-opensslextra --enable-certext --enable-tlsx --enable-oldtls --enable-tlsv10 --enable-indef --enable-psk
    make -j$(nproc)

# Build wolfSSL fuzzers
    cd $SRC/fuzzers/wolfssl/wolfssl/wolfssl-fuzzers

    make -B fuzzer-misc
    make -B fuzzer-crl
    make -B fuzzer-ocsp

    cp fuzzer-misc $OUT/fuzzer-wolfssl-misc
    cp fuzzer-crl $OUT/fuzzer-wolfssl-crl
    cp fuzzer-ocsp $OUT/fuzzer-wolfssl-ocsp
