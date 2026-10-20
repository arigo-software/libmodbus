/*
 * Regression tests for the UDP receive-path memory-safety issues found while
 * investigating a "malloc(): corrupted top size" crash reported against the
 * UDP backend (v3.1.6-arigo).
 *
 * Root causes covered:
 *
 *  1. _modbus_receive_msg() used to hand the UDP backend's
 *     max_adu_length (512) to recv(), regardless of the real size of the
 *     caller's buffer. Every internal confirmation buffer in modbus.c is
 *     only MAX_MESSAGE_LENGTH (260) bytes, so any UDP datagram longer than
 *     260 bytes (legitimate oversized response, stray/garbage datagram,
 *     ...) overflowed that buffer - on the stack for most functions, and on
 *     the heap for callers of the public modbus_receive_confirmation() API
 *     that follow the documented MODBUS_MAX_ADU_LENGTH contract.
 *
 *  2. modbus_read_objects() copied a number of bytes taken verbatim from
 *     the wire-provided "frameLength" field of a Read Object response into
 *     the caller-supplied 'dest' buffer, completely ignoring the 'len'
 *     parameter that describes dest's real capacity, and without checking
 *     that the response actually contained that many bytes. A malformed,
 *     truncated, or merely larger-than-expected response caused an
 *     out-of-bounds read of the internal response buffer and an unbounded
 *     write into 'dest' - a direct path to heap corruption when 'dest' is
 *     heap-allocated by the caller, matching the reported symptom.
 *
 *  3. The UDP-PI backend reused the plain-UDP send/recv functions, which
 *     cast ctx->backend_data to modbus_udp_t* even though UDP-PI contexts
 *     actually store a (differently laid out) modbus_udp_pi_t*. The
 *     resulting sockaddr/addr_len came from the wrong struct offsets,
 *     landing inside the 'node' string and containing uninitialized heap
 *     memory, which made every UDP-PI request fail (sendto() sees a
 *     garbage, usually unsupported, address family).
 *
 * This test exercises the fixes end-to-end over real loopback UDP sockets,
 * with a fake "server" that sends back deliberately crafted, oversized,
 * truncated, or malformed responses. It is meant to be built with
 * -fsanitize=address,undefined so that any regression back into the old
 * behaviour aborts the test binary immediately instead of silently
 * "working" with corrupted memory.
 *
 * Build (from the repository root):
 *   gcc -g -O1 -fsanitize=address,undefined -Isrc -I. \
 *       tests/regression-udp-memory.c \
 *       src/modbus.c src/modbus-udp.c src/modbus-tcp.c src/modbus-rtu.c \
 *       src/modbus-data.c -lpthread -o /tmp/regression-udp-memory
 *   /tmp/regression-udp-memory
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "modbus.h"

#define MODBUS_FC_READ_OBJECT_T 0x34

static int g_failures = 0;

#define CHECK(cond, fmt, ...) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL (%s:%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
            g_failures++; \
        } else { \
            printf("  ok: " fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)

/* Builds an MBAP header matching 'req' (same transaction id and slave id)
   followed by 'payload'/'payload_len', into 'out'. Returns the total
   length. 'declared_len' is written into MBAP bytes 4-5 (it is allowed to
   be a lie, to simulate malformed responses); it has no effect on Read/
   Write Object confirmations, which libmodbus validates differently. */
static int build_response(const uint8_t *req, uint8_t *out,
                          const uint8_t *payload, int payload_len,
                          int declared_len)
{
    out[0] = req[0];
    out[1] = req[1];
    out[2] = 0;
    out[3] = 0;
    out[4] = (declared_len >> 8) & 0xFF;
    out[5] = declared_len & 0xFF;
    out[6] = req[6];
    if (payload_len > 0) {
        memcpy(out + 7, payload, payload_len);
    }
    return 7 + payload_len;
}

static int make_bound_udp_socket(int *bound_port)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) < 0) {
        close(fd);
        return -1;
    }
    *bound_port = ntohs(addr.sin_port);
    return fd;
}

/* Runs 'client_fn' (the libmodbus call under test) on a background thread
   while this thread plays the server: wait for exactly one datagram, then
   hand it to 'respond_fn', which crafts and sends the reply (or does
   nothing, to simulate a dropped/never-sent response). */
typedef void (*respond_fn_t)(int fd, const struct sockaddr_in *peer,
                             const uint8_t *req, int req_len, void *user);

typedef struct {
    modbus_t *ctx;
    int (*client_fn)(modbus_t *ctx, void *user);
    void *client_user;
    int result;
} client_thread_arg_t;

static void *client_thread_main(void *arg)
{
    client_thread_arg_t *a = (client_thread_arg_t *)arg;
    a->result = a->client_fn(a->ctx, a->client_user);
    return NULL;
}

static int run_exchange(modbus_t *ctx,
                        int (*client_fn)(modbus_t *ctx, void *user), void *client_user,
                        respond_fn_t respond_fn, void *respond_user,
                        int server_fd)
{
    pthread_t client_thread;
    client_thread_arg_t carg = { ctx, client_fn, client_user, -2 };

    pthread_create(&client_thread, NULL, client_thread_main, &carg);

    uint8_t req[600];
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    int rc = recvfrom(server_fd, req, sizeof(req), 0,
                      (struct sockaddr *)&peer, &peer_len);
    if (rc > 0 && respond_fn != NULL) {
        respond_fn(server_fd, &peer, req, rc, respond_user);
    }

    pthread_join(client_thread, NULL);
    return carg.result;
}

/* ---- client bodies ---- */

typedef struct {
    uint8_t type;
    uint16_t field;
    uint16_t start;
    uint8_t count;
    uint16_t len;
    uint8_t *dest;
    int rc;
    int err;
} read_objects_args_t;

static int client_read_objects(modbus_t *ctx, void *user)
{
    read_objects_args_t *a = (read_objects_args_t *)user;
    a->rc = modbus_read_objects(ctx, a->type, a->field, a->start, a->count, a->len, a->dest);
    a->err = errno;
    return a->rc;
}

typedef struct {
    uint16_t *dest;
    int nb;
    int rc;
    int err;
} read_registers_args_t;

static int client_read_registers(modbus_t *ctx, void *user)
{
    read_registers_args_t *a = (read_registers_args_t *)user;
    a->rc = modbus_read_registers(ctx, 0, a->nb, a->dest);
    a->err = errno;
    return a->rc;
}

/* ---- responders ---- */

typedef struct {
    const uint8_t *payload;
    int payload_len;
} canned_payload_t;

static void respond_with_payload(int fd, const struct sockaddr_in *peer,
                                 const uint8_t *req, int req_len, void *user)
{
    (void)req_len;
    canned_payload_t *p = (canned_payload_t *)user;
    uint8_t out[700];
    int len = build_response(req, out, p->payload, p->payload_len, p->payload_len + 1);
    sendto(fd, out, len, 0, (const struct sockaddr *)peer, sizeof(*peer));
}

static void respond_with_raw_garbage(int fd, const struct sockaddr_in *peer,
                                     const uint8_t *req, int req_len, void *user)
{
    (void)req;
    (void)req_len;
    int *garbage_len = (int *)user;
    uint8_t out[600];
    memset(out, 0x5A, sizeof(out));
    int n = *garbage_len;
    if (n > (int)sizeof(out)) n = sizeof(out);
    sendto(fd, out, n, 0, (const struct sockaddr *)peer, sizeof(*peer));
}

static void respond_read_registers_ok(int fd, const struct sockaddr_in *peer,
                                      const uint8_t *req, int req_len, void *user)
{
    (void)user;
    (void)req_len;
    uint8_t payload[2 + 2 * 16];
    payload[0] = 0x03; /* MODBUS_FC_READ_HOLDING_REGISTERS */
    payload[1] = 2 * 16;
    for (int i = 0; i < 16; i++) {
        payload[2 + 2 * i] = 0;
        payload[2 + 2 * i + 1] = (uint8_t)i;
    }
    uint8_t out[600];
    int len = build_response(req, out, payload, sizeof(payload), sizeof(payload) + 1);
    sendto(fd, out, len, 0, (const struct sockaddr *)peer, sizeof(*peer));
}

/* ======================================================================= */
/* Object extension: large valid telegram must still work (UDP keeps its   */
/* larger transport capacity for the Object extension).                    */
/* ======================================================================= */
static void test_object_large_valid(void)
{
    printf("test_object_large_valid\n");
    int port;
    int server_fd = make_bound_udp_socket(&port);
    CHECK(server_fd >= 0, "server socket bound");

    modbus_t *ctx = modbus_new_udp("127.0.0.1", port);
    modbus_connect(ctx);

    const int N = 400;
    static uint8_t payload[11 + 400];
    payload[0] = MODBUS_FC_READ_OBJECT_T;
    int frameLength = N + 12; /* matches the data_offset(11)+1 adjustment in modbus_read_objects */
    payload[1] = (frameLength >> 8) & 0xFF;
    payload[2] = frameLength & 0xFF;
    payload[3] = 1; payload[4] = 7;
    payload[5] = 0; payload[6] = 1;
    payload[7] = 0; payload[8] = 1;
    payload[9] = 0; payload[10] = 1;
    for (int i = 0; i < N; i++) payload[11 + i] = (uint8_t)(0xA0 + (i & 0x0F));

    canned_payload_t cp = { payload, (int)sizeof(payload) };

    uint8_t *dest = malloc(N); /* heap, exact size: ASan catches any overflow */
    read_objects_args_t args = { 7, 0, 1, 1, N, dest, -2, 0 };

    int rc = run_exchange(ctx, client_read_objects, &args,
                          respond_with_payload, &cp, server_fd);

    CHECK(rc == N, "modbus_read_objects returned %d data bytes (expected %d)", rc, N);
    if (rc == N) {
        int ok = 1;
        for (int i = 0; i < N; i++) {
            if (dest[i] != (uint8_t)(0xA0 + (i & 0x0F))) { ok = 0; break; }
        }
        CHECK(ok, "copied data matches what the server sent");
    }

    free(dest);
    modbus_free(ctx);
    close(server_fd);
}

/* ======================================================================= */
/* Object extension: destination buffer smaller than the response must be  */
/* rejected, never overflowed (this is the direct fix for the heap-        */
/* corruption-causing bug: 'len' used to be ignored entirely).             */
/* ======================================================================= */
static void test_object_dest_too_small(void)
{
    printf("test_object_dest_too_small\n");
    int port;
    int server_fd = make_bound_udp_socket(&port);
    CHECK(server_fd >= 0, "server socket bound");

    modbus_t *ctx = modbus_new_udp("127.0.0.1", port);
    modbus_connect(ctx);

    const int N = 400;
    static uint8_t payload[11 + 400];
    payload[0] = MODBUS_FC_READ_OBJECT_T;
    int frameLength = N + 12;
    payload[1] = (frameLength >> 8) & 0xFF;
    payload[2] = frameLength & 0xFF;
    payload[3] = 1; payload[4] = 7;
    payload[5] = 0; payload[6] = 1;
    payload[7] = 0; payload[8] = 1;
    payload[9] = 0; payload[10] = 1;
    for (int i = 0; i < N; i++) payload[11 + i] = (uint8_t)(0xA0 + (i & 0x0F));

    canned_payload_t cp = { payload, (int)sizeof(payload) };

    const int dest_cap = 64; /* much smaller than the 400 bytes the server sends */
    uint8_t *dest = malloc(dest_cap); /* ASan redzone right after this */
    read_objects_args_t args = { 7, 0, 1, 1, dest_cap, dest, -2, 0 };

    int rc = run_exchange(ctx, client_read_objects, &args,
                          respond_with_payload, &cp, server_fd);

    CHECK(rc == -1, "modbus_read_objects rejects an oversized response instead of overflowing dest (rc=%d)", rc);
    CHECK(args.err == EMBMDATA, "errno is EMBMDATA (got %d)", args.err);

    free(dest);
    modbus_free(ctx);
    close(server_fd);
}

/* ======================================================================= */
/* Object extension: a response that lies about its own length (frameLength*/
/* far exceeding what was actually sent) must be rejected rather than read */
/* out of bounds / copied into dest.                                       */
/* ======================================================================= */
static void test_object_invalid_framelength(void)
{
    printf("test_object_invalid_framelength\n");
    int port;
    int server_fd = make_bound_udp_socket(&port);
    CHECK(server_fd >= 0, "server socket bound");

    modbus_t *ctx = modbus_new_udp("127.0.0.1", port);
    modbus_connect(ctx);

    /* Server claims a huge frameLength (0xFFFF) but only actually sends the
       11-byte fixed header - i.e. a malicious/corrupt device lying about
       how much data follows. Without the 'available' clamp, modbus_read_
       objects() would read ~64KB past a 522-byte stack buffer and then
       "copy" that into dest. */
    uint8_t payload[11];
    payload[0] = MODBUS_FC_READ_OBJECT_T;
    payload[1] = 0xFF; payload[2] = 0xFF; /* frameLength: a lie */
    payload[3] = 1; payload[4] = 7;
    payload[5] = 0; payload[6] = 1;
    payload[7] = 0; payload[8] = 1;
    payload[9] = 0; payload[10] = 1;

    canned_payload_t cp = { payload, (int)sizeof(payload) };

    uint8_t *dest = malloc(512);
    read_objects_args_t args = { 7, 0, 1, 1, 512, dest, -2, 0 };

    int rc = run_exchange(ctx, client_read_objects, &args,
                          respond_with_payload, &cp, server_fd);

    CHECK(rc == -1, "a lying frameLength is rejected, not trusted (rc=%d)", rc);
    CHECK(args.err == EMBBADDATA, "errno is EMBBADDATA (got %d)", args.err);

    free(dest);
    modbus_free(ctx);
    close(server_fd);
}

/* ======================================================================= */
/* Object extension: a response far shorter than the fixed header must be  */
/* rejected, not parsed with garbage/uninitialized field values.           */
/* ======================================================================= */
static void test_object_short_response(void)
{
    printf("test_object_short_response\n");
    int port;
    int server_fd = make_bound_udp_socket(&port);
    CHECK(server_fd >= 0, "server socket bound");

    modbus_t *ctx = modbus_new_udp("127.0.0.1", port);
    modbus_connect(ctx);

    /* Just the function code, nothing else - far too short to be a valid
       Read Object response. */
    uint8_t payload[1] = { MODBUS_FC_READ_OBJECT_T };
    canned_payload_t cp = { payload, (int)sizeof(payload) };

    uint8_t *dest = malloc(64);
    read_objects_args_t args = { 7, 0, 1, 1, 64, dest, -2, 0 };

    int rc = run_exchange(ctx, client_read_objects, &args,
                          respond_with_payload, &cp, server_fd);

    CHECK(rc == -1, "a too-short response is rejected (rc=%d)", rc);
    CHECK(args.err == EMBBADDATA, "errno is EMBBADDATA (got %d)", args.err);

    free(dest);
    modbus_free(ctx);
    close(server_fd);
}

/* ======================================================================= */
/* Generic (non-Object) path: a truncated/oversized UDP datagram answering */
/* an ordinary function must be rejected, not overflow the 260-byte        */
/* internal stack buffer used throughout modbus.c. This reproduces the     */
/* exact shape of the bug confirmed earlier with ASan (260-byte buffer,    */
/* 300+-byte datagram).                                                    */
/* ======================================================================= */
static void test_generic_truncated_datagram(void)
{
    printf("test_generic_truncated_datagram\n");
    int port;
    int server_fd = make_bound_udp_socket(&port);
    CHECK(server_fd >= 0, "server socket bound");

    modbus_t *ctx = modbus_new_udp("127.0.0.1", port);
    modbus_connect(ctx);

    int garbage_len = 400; /* > MAX_MESSAGE_LENGTH (260), <= MODBUS_UDP_MAX_ADU_LENGTH (512) */
    uint16_t dest[16];
    read_registers_args_t args = { dest, 16, -2, 0 };

    int rc = run_exchange(ctx, client_read_registers, &args,
                          respond_with_raw_garbage, &garbage_len, server_fd);

    CHECK(rc == -1, "oversized/garbage UDP datagram on the generic path is rejected (rc=%d)", rc);
    CHECK(args.err == EMBBADDATA, "errno is EMBBADDATA (got %d)", args.err);

    modbus_free(ctx);
    close(server_fd);
}

/* ======================================================================= */
/* Generic (non-Object) path: a normal, correctly-sized exchange must keep */
/* working after the fix (no regression for everyday UDP use).            */
/* ======================================================================= */
static void test_generic_normal_exchange_still_works(void)
{
    printf("test_generic_normal_exchange_still_works\n");
    int port;
    int server_fd = make_bound_udp_socket(&port);
    CHECK(server_fd >= 0, "server socket bound");

    modbus_t *ctx = modbus_new_udp("127.0.0.1", port);
    modbus_connect(ctx);

    uint16_t dest[16];
    memset(dest, 0xFF, sizeof(dest));
    read_registers_args_t args = { dest, 16, -2, 0 };

    int rc = run_exchange(ctx, client_read_registers, &args,
                          respond_read_registers_ok, NULL, server_fd);

    CHECK(rc == 16, "normal UDP read_registers exchange still returns the right count (rc=%d)", rc);
    int ok = 1;
    for (int i = 0; i < 16; i++) if (dest[i] != i) ok = 0;
    CHECK(ok, "normal UDP read_registers exchange returns correct values");

    modbus_free(ctx);
    close(server_fd);
}

/* ======================================================================= */
/* UDP-PI: proves send/recv now operate on the right struct                */
/* (modbus_udp_pi_t) by completing an ordinary round trip - with the old   */
/* aliasing bug, sendto() would see a garbage/unsupported address family   */
/* read from the wrong struct offsets and fail outright.                   */
/* ======================================================================= */
static void test_udp_pi_round_trip(void)
{
    printf("test_udp_pi_round_trip\n");
    int port;
    int server_fd = make_bound_udp_socket(&port);
    CHECK(server_fd >= 0, "server socket bound");

    char service[16];
    snprintf(service, sizeof(service), "%d", port);
    modbus_t *ctx = modbus_new_udp_pi("127.0.0.1", service);
    CHECK(ctx != NULL, "modbus_new_udp_pi");
    int crc = modbus_connect(ctx);
    CHECK(crc == 0, "modbus_connect (udp-pi) succeeds (rc=%d, errno=%d)", crc, errno);

    uint16_t dest[16];
    memset(dest, 0xFF, sizeof(dest));
    read_registers_args_t args = { dest, 16, -2, 0 };

    int rc = run_exchange(ctx, client_read_registers, &args,
                          respond_read_registers_ok, NULL, server_fd);

    CHECK(rc == 16, "UDP-PI read_registers round trip succeeds (rc=%d, errno=%d)", rc, args.err);

    modbus_free(ctx);
    close(server_fd);
}

/* ======================================================================= */
/* TCP sanity/regression check: the shared receive-path signature change   */
/* must not affect the TCP backend.                                        */
/* ======================================================================= */
static void *tcp_server_thread(void *arg)
{
    int listen_fd = *(int *)arg;
    int conn = accept(listen_fd, NULL, NULL);
    if (conn < 0) return NULL;

    uint8_t req[300];
    int n = read(conn, req, sizeof(req));
    if (n > 0) {
        uint8_t payload[2 + 2 * 16];
        payload[0] = 0x03;
        payload[1] = 2 * 16;
        for (int i = 0; i < 16; i++) {
            payload[2 + 2 * i] = 0;
            payload[2 + 2 * i + 1] = (uint8_t)i;
        }
        uint8_t out[600];
        int len = build_response(req, out, payload, sizeof(payload), sizeof(payload) + 1);
        if (write(conn, out, len) < 0) {
            perror("write");
        }
    }
    close(conn);
    return NULL;
}

static void test_tcp_regression(void)
{
    printf("test_tcp_regression\n");
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listen_fd, 1);
    getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len);
    int port = ntohs(addr.sin_port);

    pthread_t srv_thread;
    pthread_create(&srv_thread, NULL, tcp_server_thread, &listen_fd);

    modbus_t *ctx = modbus_new_tcp("127.0.0.1", port);
    CHECK(modbus_connect(ctx) == 0, "TCP connect succeeds");

    uint16_t dest[16];
    memset(dest, 0xFF, sizeof(dest));
    int rc = modbus_read_registers(ctx, 0, 16, dest);
    CHECK(rc == 16, "TCP read_registers still works after the shared receive-path change (rc=%d)", rc);

    pthread_join(srv_thread, NULL);
    modbus_free(ctx);
    close(listen_fd);
}

int main(void)
{
    test_object_large_valid();
    test_object_dest_too_small();
    test_object_invalid_framelength();
    test_object_short_response();
    test_generic_truncated_datagram();
    test_generic_normal_exchange_still_works();
    test_udp_pi_round_trip();
    test_tcp_regression();

    if (g_failures == 0) {
        printf("\nALL TESTS PASSED\n");
        return 0;
    } else {
        printf("\n%d TEST(S) FAILED\n", g_failures);
        return 1;
    }
}
