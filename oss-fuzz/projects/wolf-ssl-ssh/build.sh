#!/bin/bash -eu

# Global configuration
export LIBFUZZER_A_PATH="$LIB_FUZZING_ENGINE"
export FUZZERS_INCLUDE_PATH=$(realpath $SRC/fuzzers/include)
export WOLFSSL_BASE_CONFIGURE_PARAMS="--enable-static --disable-examples --disable-crypttests --disable-asm"
if [[ $CFLAGS = *sanitize=memory* ]]
then
    export WOLFSSL_BASE_CONFIGURE_PARAMS="$WOLFSSL_BASE_CONFIGURE_PARAMS --disable-asm"
fi

# Patch wolfSSL
    cd $SRC/wolfssl

    # Apply patches if desired

# Patch wolfSSH
    cd $SRC/wolfssh

    # Apply patches if desired

# Install fuzzing headers
    cd $SRC/fuzzing-headers
    ./install.sh

# Build libfuzzer-gv -- needed for intensity and allocation guided fuzzing
    cd $SRC/libfuzzer-gv
    # Some patches to make libfuzzer-gv compile in this environment
        sed -i 's/ALWAYS_INLINE//g' *.h *.cpp
        sed -i 's/^.*__attribute__((always_inline)).*$//g' FuzzerDefs.h
        sed -i 's/clang++/clang++ -stdlib=libc++/g' Makefile
        if [[ $CFLAGS = *fsanitize=memory* ]]
        then
            sed -i 's/clang++/clang++ -fsanitize=memory/g' Makefile
        fi
    make -j$(nproc)
    export LIBFUZZER_GV_A_PATH=$(realpath libFuzzer.a)

# Build wolfSSL + fuzzers
    /bin/bash $SRC/build_wolfssl_fuzzers.sh

# Build wolfSSH + fuzzers
    # Build wolfSSH + wolfSSL + fuzzers
    /bin/bash $SRC/build_wolfssh_fuzzers.sh
