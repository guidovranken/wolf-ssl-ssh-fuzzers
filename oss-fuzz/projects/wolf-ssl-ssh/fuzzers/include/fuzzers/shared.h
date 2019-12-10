#include <wolfssl/options.h>
#if !defined(FUZZER_WOLFSSH)
#include <wolfssl/ssl.h>
#endif
#include <stdio.h>
#include <libgen.h>
#include <stdint.h>

/* Define IO_MEMORY_CHECKS to:
 * -> Verify that outbound data is a valid memory region
 *    and does not contain uninitialized bytes, via the send hook.
 * -> Verify that inbound data buffer is a valid memory region,
 *    via the recv hook.
 *
 * These checks incur a slowdown.
 */
//#define IO_MEMORY_CHECKS

/* Abstraction of wolfSSL/wolfSSH IO error codes */
#if defined(FUZZER_WOLFSSH)
 #define IO_ERROR_GENERAL    WS_CBIO_ERR_GENERAL
 #define IO_ERROR_CONN_RST   WS_CBIO_ERR_CONN_RST
 #define IO_ERROR_ISR        WS_CBIO_ERR_ISR
 #define IO_ERROR_CONN_CLOSE WS_CBIO_ERR_CONN_CLOSE
 #define IO_ERROR_TIMEOUT    WS_CBIO_ERR_TIMEOUT
#else
 #define IO_ERROR_GENERAL    WOLFSSL_CBIO_ERR_CONN_CLOSE
 #define IO_ERROR_CONN_RST   WOLFSSL_CBIO_ERR_CONN_RST
 #define IO_ERROR_ISR        WOLFSSL_CBIO_ERR_GENERAL
 #define IO_ERROR_CONN_CLOSE WOLFSSL_CBIO_ERR_ISR
 #define IO_ERROR_TIMEOUT    WOLFSSL_CBIO_ERR_TIMEOUT
#endif

/* The number of pointers that may be used to track allocation usage */
#define NUM_ALLOCATION_POINTERS 4096

/* The custom allocator functions will return BADPTR if 0 bytes are requested.
 * This tests if pointers to buffers of size 0 are dereferenced.
 * That shouldn't happen, and if it does, it's a bug in wolfSSL.
 *
 * This trick is required because AddressSanitizer does currently not detect this behavior.
 */
#define BADPTR ((void*)0x12)

/* libFuzzer-supplied input data */
static const uint8_t* fuzzer_data;
static size_t fuzzer_data_size;

/* Options */
static int have_io_randomization = 0;
static int have_allocation_randomization = 0;
static int have_allocation_metering = 0;

/* Start allocation metering */
    static size_t single_peak_allocation = 0;
    static size_t collective_peak_allocation = 0;
    static void* allocation_pointers[NUM_ALLOCATION_POINTERS];
    static size_t allocation_sizes[NUM_ALLOCATION_POINTERS];

    static void update_single_peak_allocation(size_t n) {
        if ( !have_allocation_metering ) return;

        if ( n > single_peak_allocation ) {
            single_peak_allocation = n;
            printf("peak (single) %zu\n", n);
        }
    }

    void reset_single_peak_allocation(void) {
        single_peak_allocation = 0;
    }

    static int find_allocation_pointer_index(const void* p) {
        int i;

        for (i = 0; i < NUM_ALLOCATION_POINTERS; i++) {
            if ( allocation_pointers[i] == p ) {
                break;
            }
        }

        return i == NUM_ALLOCATION_POINTERS ? -1 : i;
    }

    static void update_collective_peak_allocation(void) {
        size_t cur_allocation = 0;
        for (int i = 0; i < NUM_ALLOCATION_POINTERS; i++) {
            cur_allocation += allocation_sizes[i];
        }

        if ( cur_allocation > collective_peak_allocation ) {
            collective_peak_allocation = cur_allocation;
            printf("peak (collective) %zu\n", cur_allocation);
        }
    }

    static void collective_peak_alloc(void* p, size_t n, int _realloc) {
        if ( !have_allocation_metering ) return;
        if ( p == BADPTR ) return;

        const int i = find_allocation_pointer_index(_realloc ? p : NULL);

        if ( i == -1 ) {
            return;
        }

        if ( _realloc && allocation_sizes[i] > n ) {
            abort();
        }

        allocation_pointers[i] = p;
        allocation_sizes[i] = n;

        update_collective_peak_allocation();
    }

    static void collective_peak_free(const void* p) {
        if ( !have_allocation_metering ) return;
        if ( p == BADPTR ) return;

        const int i = find_allocation_pointer_index(p);

        if ( i == -1 ) {
            return;
        }

        allocation_pointers[i] = NULL;
        allocation_sizes[i] = 0;
    }

    size_t get_single_peak_allocation(void) {
        return single_peak_allocation;
    }

    void reset_collective_peak_allocation(void) {
        memset(allocation_pointers, 0, sizeof(allocation_pointers));
        memset(allocation_sizes, 0, sizeof(allocation_sizes));
    }
/* End allocation metering */

size_t get_collective_peak_allocation(void) {
    return collective_peak_allocation;
}

static int randomize_allocation_result(void) {
    if ( have_allocation_randomization ) {
        if ( fuzzer_data_size ) {
            /* Get one byte to determine success or failure */
            const uint8_t choice = *fuzzer_data;

            /* Advance input pointers */
            fuzzer_data++; fuzzer_data_size--;

            if ( (choice % 2) == 0 ) {
                /* Allocation should fail */
                return 0;
            } else {
                /* Allocation should succeed */
                return 1;
            }
        } else {
            /* No input left to determine whether allocation should succeed or fail,
             * so return failure */
            return 0;
        }
    } else {
        /* No IO randomization -- allocations always succeed */
        return 1;
    }
}

/* Start of custom allocators */
    static void* wolfCrypt_custom_malloc(size_t n) {
        if ( !randomize_allocation_result() ) return NULL;
        update_single_peak_allocation(n);
        void* ptr = n == 0 ? BADPTR : malloc(n);
        collective_peak_alloc(ptr, n, 0);
        return ptr;
    }

    static void* wolfCrypt_custom_realloc(void* ptr, size_t n) {
        if ( !randomize_allocation_result() ) return NULL;
        collective_peak_alloc(ptr, n, 1);
        update_single_peak_allocation(n);
        if ( ptr == BADPTR ) return wolfCrypt_custom_malloc(n);
        return realloc(ptr, n);
    }

    static void wolfCrypt_custom_free(void* ptr) {
        collective_peak_free(ptr);
        if ( ptr == BADPTR ) return;
        free(ptr);
    }
/* End of custom allocators */


/* Start of option setters */
    void enable_allocation_metering(void) {
        have_allocation_metering = 1;
    }

    void enable_allocation_randomization(void) {
        have_allocation_randomization = 1;
    }

    void enable_io_randomization(void) {
        have_io_randomization = 1;
    }
/* End of option setters */

void fuzzer_set_data(const uint8_t* data, size_t size)
{
    fuzzer_data = data;
    fuzzer_data_size = size;
}

void fuzzer_unset_data(void)
{
    fuzzer_data = NULL;
    fuzzer_data_size = 0;
}

/* Start of IO overrides */
#if defined(FUZZER_WOLFSSH)
    int fuzzer_send(WOLFSSH* ctx, void* buf, word32 sz, void* x)
#else
    int fuzzer_send(WOLFSSL* ctx, char* buf, int sz, void* x)
#endif
    {
        (void)ctx;
        (void)x;

#if defined(IO_MEMORY_CHECKS)
        if ( sz > 0 ) {
            FILE* fp = fopen("/dev/null", "wb");
            fwrite(buf, sz, 1, fp);
            fclose(fp);
        }
#endif

        if ( have_io_randomization ) {
            uint8_t io_error;
            if ( fuzzer_data_size ) {
                io_error = *fuzzer_data;

                /* Advance input pointers */
                fuzzer_data++; fuzzer_data_size--;

            } else {
                io_error = 0xFF;
            }

            switch ( io_error ) {
                case    0:
                    return IO_ERROR_GENERAL;
                case    1:
                    return IO_ERROR_CONN_RST;
                case    2:
                    return IO_ERROR_ISR;
                case    3:
                    return IO_ERROR_CONN_CLOSE;
                case    4:
                    return IO_ERROR_TIMEOUT;
                default:
                    {
                        if ( sz == 0 || fuzzer_data_size < sizeof(uint32_t) ) {
                            return sz;
                        }

                        /* Determine how many bytes of "written" bytes (between 1..sz)*/
                        uint32_t sz2;
                        memcpy(&sz2, fuzzer_data, sizeof(sz2));

                        /* Advance input pointers */
                        fuzzer_data += sizeof(sz2); fuzzer_data_size -= sizeof(sz2);

                        /* May not exceed requested number of bytes to write */
                        if ( sz2 > sz ) {
                            sz2 = sz;
                        }

                        return sz2;
                    }
            }
        } else {
            /* Regular write -- emulate a full write */
            return sz;
        }
    }

#if defined(FUZZER_WOLFSSH)
    int fuzzer_recv(WOLFSSH* ctx, void* buf, word32 sz, void* x)
#else
    int fuzzer_recv(WOLFSSL* ctx, char* buf, int sz, void* x)
#endif
    {
        (void)ctx;
        (void)x;

        /* Returning success for a request of 0 bytes may result in infinite loops */
        if ( sz == 0 ) return IO_ERROR_CONN_RST;

        if ( fuzzer_data_size == 0 ) return IO_ERROR_CONN_RST;

#if defined(IO_MEMORY_CHECKS)
        memset(buf, 0, sz);
#endif

        if ( have_io_randomization ) {
            uint8_t io_error;
            if ( fuzzer_data_size ) {
                io_error = *fuzzer_data;

                /* Advance input pointers */
                fuzzer_data++; fuzzer_data_size--;
            } else {
                io_error = 0xFF;
            }

            switch ( io_error ) {
                case    0:
                    return IO_ERROR_GENERAL;
                case    1:
                    return IO_ERROR_CONN_RST;
                case    2:
                    return IO_ERROR_ISR;
                case    3:
                    return IO_ERROR_CONN_CLOSE;
                case    4:
                    return IO_ERROR_TIMEOUT;
                default:
                    {
                        if ( fuzzer_data_size < sizeof(uint32_t) ) {
                            return IO_ERROR_CONN_RST;
                        }

                        uint32_t sz2;
                        /* Determine how many bytes are going to be provided to the caller (between 1..sz)*/
                        {
                            memcpy(&sz2, fuzzer_data, sizeof(sz2));

                            /* Advance input pointers */
                            fuzzer_data += sizeof(sz2); fuzzer_data_size -= sizeof(sz2);

                            if ( sz2 > sz ) {
                                sz2 = sz;
                            }

                            if ( sz2 > fuzzer_data_size ) {
                                sz2 = fuzzer_data_size;
                            }
                        }

                        /* Provide the data to the caller */
                        memcpy(buf, fuzzer_data, sz2);

                        /* Advance input pointers */
                        fuzzer_data += sz2; fuzzer_data_size -= sz2;

                        return sz2;
                    }
            }
        } else {
            /* Regular read -- provide what is available */
            const int numRead = fuzzer_data_size >= sz ? sz : fuzzer_data_size;

            memcpy(buf, fuzzer_data, numRead);

            fuzzer_data += numRead;
            fuzzer_data_size -= numRead;

            return numRead;
        }
    }
/* End of IO overrides */

/* Start initialization */
    void fuzzer_install_memory_allocator(void)
    {
        if ( wolfSSL_SetAllocators(wolfCrypt_custom_malloc, wolfCrypt_custom_free, wolfCrypt_custom_realloc) != 0 ) {
            abort();
        }
    }

    void fuzzer_initialize(const int argc, char** argv) {
#if !defined(FUZZER_WOLFSSH)
        wolfSSL_Init();
#endif

        fuzzer_install_memory_allocator();

        for (int i = 1; i < argc; i++) {
            if ( argv[i][0] == '-' && argv[i][1] == '-' ) {
                if ( !strcmp(argv[i], "--randomize-io") ) {
                    enable_io_randomization();
                } else if ( !strcmp(argv[i], "--randomize-alloc") ) {
                    /* Will be handled in fuzzer_post_initialize() */
                } else {
                    printf("Invalid parameter: %s\n", argv[i]);
                    exit(0);
                }
            }
        }
    }

    void fuzzer_post_initialize(const int argc, char** argv) {
        for (int i = 1; i < argc; i++) {
            if ( !strcmp(argv[i], "--randomize-alloc") ) {
                enable_allocation_randomization();
            }
        }
    }
/* End of initialization */

static const char* get_certs_path(const char* argv0, const char* file)
{
    static char ca_cert_pem_path[8192];
    char* binary_path = strdup(argv0);
    if ( snprintf(ca_cert_pem_path, 8192, "%s/certs/%s", dirname(binary_path), file) <= 0 ) {
        abort();
    }
    free(binary_path);

    return ca_cert_pem_path;
}

#define FUZZER_INITIALIZE_HEADER \
    int LLVMFuzzerInitialize(int *argc, char ***argv) { \
        fuzzer_initialize(*argc, *argv);

#if defined(FUZZER_ALLOCATION_GUIDED)
    #define FUZZER_INITIALIZE_FOOTER_1 \
        reset_single_peak_allocation(); \
        enable_allocation_metering();
#else
    #define FUZZER_INITIALIZE_FOOTER_1
#endif

#define FUZZER_INITIALIZE_FOOTER_2 \
        fuzzer_post_initialize(*argc, *argv); \
\
        return 0; \
    }

#if defined(FUZZER_ALLOCATION_GUIDED)
    #define FUZZER_RUN_HEADER \
        int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { \
        reset_collective_peak_allocation();
    #define FUZZER_RUN_FOOTER \
        return (int)get_collective_peak_allocation(); \
    }
#else
    #define FUZZER_RUN_HEADER \
        int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    #define FUZZER_RUN_FOOTER \
        return 0; \
    }
#endif
