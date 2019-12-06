WOLFSSL_A_PATH = ../src/.libs/libwolfssl.a 

FUZZERS_CFLAGS = $(CFLAGS) -I .. -I $(FUZZERS_INCLUDE_PATH)
FUZZERS_LIBS = $(LIBFUZZER_A_PATH) $(WOLFSSL_A_PATH)
FUZZERS_LIBS_GV = $(LIBFUZZER_GV_A_PATH) $(WOLFSSL_A_PATH)

all : fuzzer-misc fuzzer-misc-intensity fuzzer-crl fuzzer-crl-intensity fuzzer-ocsp fuzzer-ocsp-intensity

misc.o : misc.c
	$(CC) $(FUZZERS_CFLAGS) misc.c -c -o misc.o
fuzzer-misc : misc.o
	$(CXX) $(CXXFLAGS) misc.o $(FUZZERS_LIBS) -o fuzzer-misc
fuzzer-misc-intensity : misc.o
	$(CXX) $(CXXFLAGS) misc.o $(FUZZERS_LIBS_GV) -o fuzzer-misc-intensity

crl.o : crl.c
	$(CC) $(FUZZERS_CFLAGS) crl.c -c -o crl.o
fuzzer-crl : crl.o
	$(CXX) $(CXXFLAGS) crl.o $(FUZZERS_LIBS) -o fuzzer-crl
fuzzer-crl-intensity : crl.o
	$(CXX) $(CXXFLAGS) crl.o $(FUZZERS_LIBS_GV) -o fuzzer-crl-intensity

ocsp.o : ocsp.c
	$(CC) $(FUZZERS_CFLAGS) ocsp.c -c -o ocsp.o
fuzzer-ocsp : ocsp.o
	$(CXX) $(CXXFLAGS) ocsp.o $(FUZZERS_LIBS) -o fuzzer-ocsp
fuzzer-ocsp-intensity : ocsp.o
	$(CXX) $(CXXFLAGS) ocsp.o $(FUZZERS_LIBS_GV) -o fuzzer-ocsp-intensity
