WOLFSSH_A_PATH = ../src/.libs/libwolfssh.a
WOLFSSL_A_PATH = ../../wolfssl/src/.libs/libwolfssl.a
WOLFSSL_A_TRACE_PC_GUARD_PATH = ../../wolfssl_trace_pc_guard/src/.libs/libwolfssl.a

FUZZERS_CFLAGS = $(CFLAGS) -DFUZZER_WOLFSSH -I .. -I $(FUZZERS_INCLUDE_PATH)
FUZZERS_LIBS = $(LIBFUZZER_A_PATH) $(WOLFSSH_A_PATH) $(WOLFSSL_A_PATH)
FUZZERS_LIBS_GV = $(LIBFUZZER_GV_A_PATH) $(WOLFSSH_A_PATH) $(WOLFSSL_A_TRACE_PC_GUARD_PATH)

all : fuzzer-client fuzzer-client-intensity fuzzer-server fuzzer-server-intensity

client.o : client.c
	$(CC) $(FUZZERS_CFLAGS) client.c -c -o client.o
fuzzer-client : client.o
	$(CXX) $(CXXFLAGS) client.o $(FUZZERS_LIBS) -o fuzzer-client
fuzzer-client-intensity : client.o
	$(CXX) $(CXXFLAGS) client.o $(FUZZERS_LIBS_GV) -o fuzzer-client-intensity

server.o : server.c
	$(CC) $(FUZZERS_CFLAGS) server.c -c -o server.o
fuzzer-server : server.o
	$(CXX) $(CXXFLAGS) server.o $(FUZZERS_LIBS) -o fuzzer-server
fuzzer-server-intensity : server.o
	$(CXX) $(CXXFLAGS) server.o $(FUZZERS_LIBS_GV) -o fuzzer-server-intensity
