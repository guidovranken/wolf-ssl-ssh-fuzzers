WOLFSSL_A_PATH = ../src/.libs/libwolfssl.a 

FUZZERS_CFLAGS = $(CFLAGS) -I .. -I $(FUZZERS_INCLUDE_PATH)
FUZZERS_LIBS = $(LIBFUZZER_A_PATH) $(WOLFSSL_A_PATH)
FUZZERS_LIBS_GV = $(LIBFUZZER_GV_A_PATH) $(WOLFSSL_A_PATH)

all : fuzzer-misc fuzzer-misc-intensity fuzzer-misc-allocation fuzzer-crl fuzzer-crl-intensity fuzzer-crl-allocation fuzzer-ocsp fuzzer-ocsp-intensity fuzzer-ocsp-allocation fuzzer-x509 fuzzer-x509-intensity fuzzer-x509-allocation

misc.o : misc.c
	$(CC) $(FUZZERS_CFLAGS) misc.c -c -o misc.o
fuzzer-misc : misc.o
	$(CXX) $(CXXFLAGS) misc.o $(FUZZERS_LIBS) -o fuzzer-misc
fuzzer-misc-intensity : misc.o
	$(CXX) $(CXXFLAGS) misc.o $(FUZZERS_LIBS_GV) -o fuzzer-misc-intensity
misc-allocation.o : misc.c
	$(CC) -DFUZZER_ALLOCATION_GUIDED $(FUZZERS_CFLAGS) misc.c -c -o misc-allocation.o
fuzzer-misc-allocation : misc-allocation.o
	$(CXX) $(CXXFLAGS) misc-allocation.o $(FUZZERS_LIBS_GV) -o fuzzer-misc-allocation

crl.o : crl.c
	$(CC) $(FUZZERS_CFLAGS) crl.c -c -o crl.o
fuzzer-crl : crl.o
	$(CXX) $(CXXFLAGS) crl.o $(FUZZERS_LIBS) -o fuzzer-crl
fuzzer-crl-intensity : crl.o
	$(CXX) $(CXXFLAGS) crl.o $(FUZZERS_LIBS_GV) -o fuzzer-crl-intensity
crl-allocation.o : crl.c
	$(CC) -DFUZZER_ALLOCATION_GUIDED $(FUZZERS_CFLAGS) crl.c -c -o crl-allocation.o
fuzzer-crl-allocation : crl-allocation.o
	$(CXX) $(CXXFLAGS) crl-allocation.o $(FUZZERS_LIBS_GV) -o fuzzer-crl-allocation

ocsp.o : ocsp.c
	$(CC) $(FUZZERS_CFLAGS) ocsp.c -c -o ocsp.o
fuzzer-ocsp : ocsp.o
	$(CXX) $(CXXFLAGS) ocsp.o $(FUZZERS_LIBS) -o fuzzer-ocsp
fuzzer-ocsp-intensity : ocsp.o
	$(CXX) $(CXXFLAGS) ocsp.o $(FUZZERS_LIBS_GV) -o fuzzer-ocsp-intensity
ocsp-allocation.o : ocsp.c
	$(CC) -DFUZZER_ALLOCATION_GUIDED $(FUZZERS_CFLAGS) ocsp.c -c -o ocsp-allocation.o
fuzzer-ocsp-allocation : ocsp-allocation.o
	$(CXX) $(CXXFLAGS) ocsp-allocation.o $(FUZZERS_LIBS_GV) -o fuzzer-ocsp-allocation

x509.o : x509.c
	$(CC) $(FUZZERS_CFLAGS) x509.c -c -o x509.o
fuzzer-x509 : x509.o
	$(CXX) $(CXXFLAGS) x509.o $(FUZZERS_LIBS) -o fuzzer-x509
fuzzer-x509-intensity : x509.o
	$(CXX) $(CXXFLAGS) x509.o $(FUZZERS_LIBS_GV) -o fuzzer-x509-intensity
x509-allocation.o : x509.c
	$(CC) -DFUZZER_ALLOCATION_GUIDED $(FUZZERS_CFLAGS) x509.c -c -o x509-allocation.o
fuzzer-x509-allocation : x509-allocation.o
	$(CXX) $(CXXFLAGS) x509-allocation.o $(FUZZERS_LIBS_GV) -o fuzzer-x509-allocation
