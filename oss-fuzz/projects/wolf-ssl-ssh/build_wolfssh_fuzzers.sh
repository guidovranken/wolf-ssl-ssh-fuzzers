#!/bin/bash -eu

rm -rf $SRC/fuzzers/wolfssh/
mkdir -p $SRC/fuzzers/wolfssh/
cp -R $SRC/wolfssh/ $SRC/fuzzers/wolfssh/
cp -R $SRC/wolfssl/ $SRC/fuzzers/wolfssh/
cp -R $SRC/fuzzers/wolfssh-fuzzers $SRC/fuzzers/wolfssh/wolfssh/

export CFLAGS="$CFLAGS -DWOLFSSL_STATIC_PSK"

# Build wolfSSL (required for wolfSSH)
    cd $SRC/fuzzers/wolfssh/wolfssl/
    autoreconf -ivf
    ./configure $WOLFSSL_BASE_CONFIGURE_PARAMS --enable-ssh --enable-keygen
    make -j$(nproc)

# Required to configure + build wolfSSH without having to install wolfSSL
    export LDFLAGS="-L$(realpath src/.libs/)"
    export CFLAGS="$CFLAGS -I $(realpath .)"

# Build wolfSSH
    cd $SRC/fuzzers/wolfssh/wolfssh/
    autoreconf -ivf
    ./configure --enable-static --enable-all --disable-examples
    make -j$(nproc)

# Build wolfSSH fuzzers
    cd $SRC/fuzzers/wolfssh/wolfssh/wolfssh-fuzzers

    make -B fuzzer-client
    make -B fuzzer-server

    cp fuzzer-client $OUT/fuzzer-wolfssh-client
    cp fuzzer-server $OUT/fuzzer-wolfssh-server
