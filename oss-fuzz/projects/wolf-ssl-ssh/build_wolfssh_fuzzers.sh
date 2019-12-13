#!/bin/bash -eu

rm -rf $SRC/fuzzers/wolfssh/
mkdir -p $SRC/fuzzers/wolfssh/
cp -R $SRC/wolfssh/ $SRC/fuzzers/wolfssh/
cp -R $SRC/wolfssl/ $SRC/fuzzers/wolfssh/
cp -R $SRC/fuzzers/wolfssh-fuzzers $SRC/fuzzers/wolfssh/wolfssh/
cp -R $SRC/fuzzers/wolfssh/wolfssl/ $SRC/fuzzers/wolfssh/wolfssl_trace_pc_guard/
cp -R $SRC/fuzzers/wolfssh/wolfssh/ $SRC/fuzzers/wolfssh/wolfssh_trace_pc_guard/

export CFLAGS="$CFLAGS -DWOLFSSL_STATIC_PSK"
export ORIGINAL_CFLAGS="$CFLAGS"

# Build everything with -fsanitize=fuzzer-no-link (normal code coverage guided fuzzing)
    # Build wolfSSL (required for wolfSSH)
        cd $SRC/fuzzers/wolfssh/wolfssl/
        autoreconf -ivf
        ./configure $WOLFSSL_BASE_CONFIGURE_PARAMS --enable-ssh --enable-keygen
        make -j$(nproc)

    # Required to configure + build wolfSSH without having to install wolfSSL
        export LDFLAGS="-L$(realpath src/.libs/)"
        export CFLAGS="$ORIGINAL_CFLAGS -I $(realpath .)"

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

        cp -R corp-client/ $OUT/corp-wolfssh-client/
        cp -R corp-server/ $OUT/corp-wolfssh-server/

# Build everything with -fsanitize-coverage=trace-pc-guard (for intensity and allocation guided fuzzing)
    if [[ $CFLAGS != *-m32* ]]
    then
        export ORIGINAL_CFLAGS=${ORIGINAL_CFLAGS/"-fsanitize=fuzzer-no-link"/"-fsanitize-coverage=trace-pc-guard"}

        # Build wolfSSL (required for wolfSSH)
            cd $SRC/fuzzers/wolfssh/wolfssl_trace_pc_guard/
            autoreconf -ivf
            ./configure $WOLFSSL_BASE_CONFIGURE_PARAMS --enable-ssh --enable-keygen
            make -j$(nproc)

        # Required to configure + build wolfSSH without having to install wolfSSL
            export LDFLAGS="-L$(realpath src/.libs/)"
            export CFLAGS="$ORIGINAL_CFLAGS -I $(realpath .)"

        # Build wolfSSH
            cd $SRC/fuzzers/wolfssh/wolfssh_trace_pc_guard/
            autoreconf -ivf
            ./configure --enable-static --enable-all --disable-examples
            make -j$(nproc)

        # Build wolfSSH fuzzers (intensity guided)
            cd $SRC/fuzzers/wolfssh/wolfssh_trace_pc_guard/wolfssh-fuzzers

            make -B fuzzer-client-intensity
            make -B fuzzer-server-intensity

            cp fuzzer-client-intensity $OUT/fuzzer-wolfssh-client-intensity
            cp fuzzer-server-intensity $OUT/fuzzer-wolfssh-server-intensity

        # Build wolfSSH fuzzers (allocation guided)
            cd $SRC/fuzzers/wolfssh/wolfssh_trace_pc_guard/wolfssh-fuzzers

            make -B fuzzer-client-allocation
            make -B fuzzer-server-allocation

            cp fuzzer-client-allocation $OUT/fuzzer-wolfssh-client-allocation
            cp fuzzer-server-allocation $OUT/fuzzer-wolfssh-server-allocation
    fi
