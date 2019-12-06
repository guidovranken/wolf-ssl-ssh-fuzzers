WOLFSSL_A_PATH = ../src/.libs/libwolfssl.a 

FUZZERS_CFLAGS = $(CFLAGS) -I .. -I $(FUZZERS_INCLUDE_PATH)
FUZZERS_LIBS = $(LIBFUZZER_A_PATH) $(WOLFSSL_A_PATH)

all : fuzzer-misc fuzzer-crl fuzzer-ocsp

misc.o : misc.c
	$(CC) $(FUZZERS_CFLAGS) misc.c -c -o misc.o
fuzzer-misc : misc.o
	$(CXX) $(CXXFLAGS) misc.o $(FUZZERS_LIBS) -o fuzzer-misc

crl.o : crl.c
	$(CC) $(FUZZERS_CFLAGS) crl.c -c -o crl.o
fuzzer-crl : crl.o
	$(CXX) $(CXXFLAGS) crl.o $(FUZZERS_LIBS) -o fuzzer-crl

ocsp.o : ocsp.c
	$(CC) $(FUZZERS_CFLAGS) ocsp.c -c -o ocsp.o
fuzzer-ocsp : ocsp.o
	$(CXX) $(CXXFLAGS) ocsp.o $(FUZZERS_LIBS) -o fuzzer-ocsp
