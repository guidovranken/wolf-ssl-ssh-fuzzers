WOLFSSH_A_PATH = ../src/.libs/libwolfssh.a
WOLFSSL_A_PATH = ../../wolfssl/src/.libs/libwolfssl.a 

FUZZERS_CFLAGS = $(CFLAGS) -DFUZZER_WOLFSSH -I .. -I $(FUZZERS_INCLUDE_PATH)
FUZZERS_LIBS = $(LIBFUZZER_A_PATH) $(WOLFSSH_A_PATH) $(WOLFSSL_A_PATH)

all : fuzzer-client fuzzer-client-intensity fuzzer-server

client.o : client.c
	$(CC) $(FUZZERS_CFLAGS) client.c -c -o client.o
fuzzer-client : client.o
	$(CXX) $(CXXFLAGS) client.o $(FUZZERS_LIBS) -o fuzzer-client

server.o : server.c
	$(CC) $(FUZZERS_CFLAGS) server.c -c -o server.o
fuzzer-server : server.o
	$(CXX) $(CXXFLAGS) server.o $(FUZZERS_LIBS) -o fuzzer-server
