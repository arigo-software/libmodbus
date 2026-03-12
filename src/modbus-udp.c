/*
 * Copyright © 2001-2013 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#if defined(_WIN32)
# define OS_WIN32
# ifndef WINVER
#   define WINVER 0x0501
# endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <signal.h>
#include <sys/types.h>

#if defined(_WIN32)
# include <winsock2.h>
# include <ws2tcpip.h>
# define SHUT_RDWR 2
# define close closesocket
#else
# include <sys/socket.h>
# include <sys/ioctl.h>

#if defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ < 5)
# define OS_BSD
# include <netinet/in_systm.h>
#endif

# include <netinet/in.h>
# include <netinet/ip.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#if defined(_AIX) && !defined(MSG_DONTWAIT)
#define MSG_DONTWAIT MSG_NONBLOCK
#endif

#include "modbus-private.h"

#include "modbus-udp.h"
#include "modbus-udp-private.h"

#ifdef OS_WIN32
static int _modbus_udp_init_win32(void)
{
    /* Initialise Windows Socket API */
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup() returned error code %d\n",
                (unsigned int)GetLastError());
        errno = EIO;
        return -1;
    }
    return 0;
}
#endif

static int _modbus_set_slave(modbus_t *ctx, int slave)
{
    /* Broadcast address is 0 (MODBUS_BROADCAST_ADDRESS) */
    if (slave >= 0 && slave <= 247) {
        ctx->slave = slave;
    } else if (slave == MODBUS_UDP_SLAVE) {
        /* The special value MODBUS_UDP_SLAVE (0xFF) can be used in UDP mode to
         * restore the default value. */
        ctx->slave = slave;
    } else {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/* Builds a UDP request header (same as TCP - uses MBAP) */
static int _modbus_udp_build_request_basis(modbus_t *ctx, int function,
                                           int addr, int nb,
                                           uint8_t *req)
{
    modbus_udp_t *ctx_udp = ctx->backend_data;

    /* Increase transaction ID */
    if (ctx_udp->t_id < UINT16_MAX)
        ctx_udp->t_id++;
    else
        ctx_udp->t_id = 0;
    req[0] = ctx_udp->t_id >> 8;
    req[1] = ctx_udp->t_id & 0x00ff;

    /* Protocol Modbus */
    req[2] = 0;
    req[3] = 0;

    /* Length will be defined later by set_req_length_udp at offsets 4
       and 5 */

    req[6] = ctx->slave;
    req[7] = function;
    req[8] = addr >> 8;
    req[9] = addr & 0x00ff;
    req[10] = nb >> 8;
    req[11] = nb & 0x00ff;

    return _MODBUS_UDP_PRESET_REQ_LENGTH;
}

/* Builds a UDP response header */
static int _modbus_udp_build_response_basis(sft_t *sft, uint8_t *rsp)
{
    /* Extract from MODBUS Messaging on TCP/IP Implementation
       Guide V1.0b (page 23/46):
       The transaction identifier is used to associate the future
       response with the request. */
    rsp[0] = sft->t_id >> 8;
    rsp[1] = sft->t_id & 0x00ff;

    /* Protocol Modbus */
    rsp[2] = 0;
    rsp[3] = 0;

    /* Length will be set later by send_msg (4 and 5) */

    /* The slave ID is copied from the indication */
    rsp[6] = sft->slave;
    rsp[7] = sft->function;

    return _MODBUS_UDP_PRESET_RSP_LENGTH;
}

static int _modbus_udp_prepare_response_tid(const uint8_t *req, int *req_length)
{
    return (req[0] << 8) + req[1];
}

static int _modbus_udp_send_msg_pre(uint8_t *req, int req_length)
{
    /* Substract the header length to the message length */
    int mbap_length = req_length - 6;

    req[4] = mbap_length >> 8;
    req[5] = mbap_length & 0x00FF;

    return req_length;
}

static ssize_t _modbus_udp_send(modbus_t *ctx, const uint8_t *req, int req_length)
{
    modbus_udp_t *ctx_udp = ctx->backend_data;

    return sendto(ctx->s, (const char *)req, req_length, MSG_NOSIGNAL,
                  (struct sockaddr *)&ctx_udp->addr, ctx_udp->addr_len);
}

static int _modbus_udp_receive(modbus_t *ctx, uint8_t *req) {
    return _modbus_receive_msg(ctx, req, MSG_INDICATION);
}

static ssize_t _modbus_udp_recv(modbus_t *ctx, uint8_t *rsp, int rsp_length) {
    modbus_udp_t *ctx_udp = ctx->backend_data;

    ctx_udp->addr_len = sizeof(ctx_udp->addr);
    return recvfrom(ctx->s, (char *)rsp, rsp_length, 0,
                    (struct sockaddr *)&ctx_udp->addr, &ctx_udp->addr_len);
}

static int _modbus_udp_check_integrity(modbus_t *ctx, uint8_t *msg, const int msg_length)
{
    return msg_length;
}

static int _modbus_udp_pre_check_confirmation(modbus_t *ctx, const uint8_t *req,
                                              const uint8_t *rsp, int rsp_length)
{
    /* Check transaction ID */
    if (req[0] != rsp[0] || req[1] != rsp[1]) {
        if (ctx->debug) {
            fprintf(stderr, "Invalid transaction ID received 0x%X (not 0x%X)\n",
                    (rsp[0] << 8) + rsp[1], (req[0] << 8) + req[1]);
        }
        errno = EMBBADDATA;
        return -1;
    }

    /* Check protocol ID */
    if (rsp[2] != 0x0 && rsp[3] != 0x0) {
        if (ctx->debug) {
            fprintf(stderr, "Invalid protocol ID received 0x%X (not 0x0)\n",
                    (rsp[2] << 8) + rsp[3]);
        }
        errno = EMBBADDATA;
        return -1;
    }

    return 0;
}

static int _modbus_udp_set_ipv4_options(int s)
{
    int rc;
    int option;

    /* If the OS does not offer SOCK_NONBLOCK, fall back to setting FIONBIO to
     * make sockets non-blocking */
    /* Do not care about the return value, this is optional */
#if !defined(SOCK_NONBLOCK) && defined(FIONBIO)
#ifdef OS_WIN32
    {
        /* Setting FIONBIO expects an unsigned long according to MSDN */
        u_long loption = 1;
        ioctlsocket(s, FIONBIO, &loption);
    }
#else
    option = 1;
    ioctl(s, FIONBIO, &option);
#endif
#endif

#ifndef OS_WIN32
    /**
     * Cygwin defines IPTOS_LOWDELAY but can't handle that flag so it's
     * necessary to workaround that problem.
     **/
    /* Set the IP low delay option */
    option = IPTOS_LOWDELAY;
    rc = setsockopt(s, IPPROTO_IP, IP_TOS,
                    (const void *)&option, sizeof(int));
    if (rc == -1) {
        return -1;
    }
#endif

    return 0;
}

/* Establishes a modbus UDP connection with a Modbus server. */
static int _modbus_udp_connect(modbus_t *ctx)
{
    int rc;
    modbus_udp_t *ctx_udp = ctx->backend_data;
    int flags = SOCK_DGRAM;

#ifdef OS_WIN32
    if (_modbus_udp_init_win32() == -1) {
        return -1;
    }
#endif

#ifdef SOCK_CLOEXEC
    flags |= SOCK_CLOEXEC;
#endif

#ifdef SOCK_NONBLOCK
    flags |= SOCK_NONBLOCK;
#endif

    ctx->s = socket(PF_INET, flags, 0);
    if (ctx->s == -1) {
        return -1;
    }

    rc = _modbus_udp_set_ipv4_options(ctx->s);
    if (rc == -1) {
        close(ctx->s);
        ctx->s = -1;
        return -1;
    }

    if (ctx->debug) {
        printf("Connecting to %s:%d (UDP)\n", ctx_udp->ip, ctx_udp->port);
    }

    /* Store destination address for sendto */
    ctx_udp->addr.sin_family = AF_INET;
    ctx_udp->addr.sin_port = htons(ctx_udp->port);
    ctx_udp->addr.sin_addr.s_addr = inet_addr(ctx_udp->ip);
    ctx_udp->addr_len = sizeof(ctx_udp->addr);

    /* UDP is connectionless - no need to connect() */
    return 0;
}

/* Establishes a modbus UDP PI connection with a Modbus server. */
static int _modbus_udp_pi_connect(modbus_t *ctx)
{
    int rc;
    struct addrinfo *ai_list;
    struct addrinfo *ai_ptr;
    struct addrinfo ai_hints;
    modbus_udp_pi_t *ctx_udp_pi = ctx->backend_data;

#ifdef OS_WIN32
    if (_modbus_udp_init_win32() == -1) {
        return -1;
    }
#endif

    memset(&ai_hints, 0, sizeof(ai_hints));
#ifdef AI_ADDRCONFIG
    ai_hints.ai_flags |= AI_ADDRCONFIG;
#endif
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_DGRAM;
    ai_hints.ai_addr = NULL;
    ai_hints.ai_canonname = NULL;
    ai_hints.ai_next = NULL;

    ai_list = NULL;
    rc = getaddrinfo(ctx_udp_pi->node, ctx_udp_pi->service,
                     &ai_hints, &ai_list);
    if (rc != 0) {
        if (ctx->debug) {
            fprintf(stderr, "Error returned by getaddrinfo: %s\n", gai_strerror(rc));
        }
        errno = ECONNREFUSED;
        return -1;
    }

    for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
        int flags = ai_ptr->ai_socktype;
        int s;

#ifdef SOCK_CLOEXEC
        flags |= SOCK_CLOEXEC;
#endif

#ifdef SOCK_NONBLOCK
        flags |= SOCK_NONBLOCK;
#endif

        s = socket(ai_ptr->ai_family, flags, ai_ptr->ai_protocol);
        if (s < 0)
            continue;

        if (ai_ptr->ai_family == AF_INET)
            _modbus_udp_set_ipv4_options(s);

        if (ctx->debug) {
            printf("Connecting to [%s]:%s (UDP)\n", ctx_udp_pi->node, ctx_udp_pi->service);
        }

        /* Store destination address */
        memcpy(&ctx_udp_pi->addr, ai_ptr->ai_addr, ai_ptr->ai_addrlen);
        ctx_udp_pi->addr_len = ai_ptr->ai_addrlen;

        ctx->s = s;
        break;
    }

    freeaddrinfo(ai_list);

    if (ctx->s < 0) {
        return -1;
    }

    return 0;
}

/* Closes the network connection and socket in UDP mode */
static void _modbus_udp_close(modbus_t *ctx)
{
    if (ctx->s != -1) {
        close(ctx->s);
        ctx->s = -1;
    }
}

static int _modbus_udp_flush(modbus_t *ctx)
{
    int rc;
    int rc_sum = 0;

    do {
        /* Extract the garbage from the socket */
        char devnull[MODBUS_UDP_MAX_ADU_LENGTH];
#ifndef OS_WIN32
        rc = recv(ctx->s, devnull, MODBUS_UDP_MAX_ADU_LENGTH, MSG_DONTWAIT);
#else
        /* On Win32, it's a bit more complicated to not wait */
        fd_set rset;
        struct timeval tv;

        tv.tv_sec = 0;
        tv.tv_usec = 0;
        FD_ZERO(&rset);
        FD_SET(ctx->s, &rset);
        rc = select(ctx->s+1, &rset, NULL, NULL, &tv);
        if (rc == -1) {
            return -1;
        }

        if (rc == 1) {
            /* There is data to flush */
            rc = recv(ctx->s, devnull, MODBUS_UDP_MAX_ADU_LENGTH, 0);
        }
#endif
        if (rc > 0) {
            rc_sum += rc;
        }
    } while (rc == MODBUS_UDP_MAX_ADU_LENGTH);

    return rc_sum;
}

/* Binds UDP socket for server (slave) mode */
int modbus_udp_bind(modbus_t *ctx)
{
    int enable;
    int flags;
    struct sockaddr_in addr;
    modbus_udp_t *ctx_udp;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    ctx_udp = ctx->backend_data;

#ifdef OS_WIN32
    if (_modbus_udp_init_win32() == -1) {
        return -1;
    }
#endif

    flags = SOCK_DGRAM;

#ifdef SOCK_CLOEXEC
    flags |= SOCK_CLOEXEC;
#endif

    ctx->s = socket(PF_INET, flags, IPPROTO_UDP);
    if (ctx->s == -1) {
        return -1;
    }

    enable = 1;
    if (setsockopt(ctx->s, SOL_SOCKET, SO_REUSEADDR,
                   (char *)&enable, sizeof(enable)) == -1) {
        close(ctx->s);
        ctx->s = -1;
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx_udp->port);
    if (ctx_udp->ip[0] == '0') {
        /* Listen any addresses */
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        /* Listen only specified IP address */
        addr.sin_addr.s_addr = inet_addr(ctx_udp->ip);
    }

    if (bind(ctx->s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(ctx->s);
        ctx->s = -1;
        return -1;
    }

    if (ctx->debug) {
        printf("UDP socket bound to %s:%d\n",
               ctx_udp->ip[0] == '0' ? "0.0.0.0" : ctx_udp->ip,
               ctx_udp->port);
    }

    return ctx->s;
}

int modbus_udp_pi_bind(modbus_t *ctx)
{
    int rc;
    struct addrinfo *ai_list;
    struct addrinfo *ai_ptr;
    struct addrinfo ai_hints;
    const char *node;
    const char *service;
    int new_s;
    modbus_udp_pi_t *ctx_udp_pi;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    ctx_udp_pi = ctx->backend_data;

#ifdef OS_WIN32
    if (_modbus_udp_init_win32() == -1) {
        return -1;
    }
#endif

    if (ctx_udp_pi->node[0] == 0) {
        node = NULL; /* == any */
    } else {
        node = ctx_udp_pi->node;
    }

    if (ctx_udp_pi->service[0] == 0) {
        service = "502";
    } else {
        service = ctx_udp_pi->service;
    }

    memset(&ai_hints, 0, sizeof (ai_hints));
    /* If node is not NULL, than the AI_PASSIVE flag is ignored. */
    ai_hints.ai_flags |= AI_PASSIVE;
#ifdef AI_ADDRCONFIG
    ai_hints.ai_flags |= AI_ADDRCONFIG;
#endif
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_DGRAM;
    ai_hints.ai_addr = NULL;
    ai_hints.ai_canonname = NULL;
    ai_hints.ai_next = NULL;

    ai_list = NULL;
    rc = getaddrinfo(node, service, &ai_hints, &ai_list);
    if (rc != 0) {
        if (ctx->debug) {
            fprintf(stderr, "Error returned by getaddrinfo: %s\n", gai_strerror(rc));
        }
        errno = ECONNREFUSED;
        return -1;
    }

    new_s = -1;
    for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
        int flags = ai_ptr->ai_socktype;
        int s;

#ifdef SOCK_CLOEXEC
        flags |= SOCK_CLOEXEC;
#endif

        s = socket(ai_ptr->ai_family, flags, ai_ptr->ai_protocol);
        if (s < 0) {
            if (ctx->debug) {
                perror("socket");
            }
            continue;
        } else {
            int enable = 1;
            rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                            (void *)&enable, sizeof (enable));
            if (rc != 0) {
                close(s);
                if (ctx->debug) {
                    perror("setsockopt");
                }
                continue;
            }
        }

        rc = bind(s, ai_ptr->ai_addr, ai_ptr->ai_addrlen);
        if (rc != 0) {
            close(s);
            if (ctx->debug) {
                perror("bind");
            }
            continue;
        }

        new_s = s;
        ctx->s = s;
        break;
    }
    freeaddrinfo(ai_list);

    if (new_s < 0) {
        return -1;
    }

    if (ctx->debug) {
        printf("UDP socket bound to %s:%s\n",
               node ? node : "any", service);
    }

    return new_s;
}

static int _modbus_udp_select(modbus_t *ctx, fd_set *rset, struct timeval *tv, int length_to_read)
{
    int s_rc;
    while ((s_rc = select(ctx->s+1, rset, NULL, NULL, tv)) == -1) {
        if (errno == EINTR) {
            if (ctx->debug) {
                fprintf(stderr, "A non blocked signal was caught\n");
            }
            /* Necessary after an error */
            FD_ZERO(rset);
            FD_SET(ctx->s, rset);
        } else {
            return -1;
        }
    }

    if (s_rc == 0) {
        errno = ETIMEDOUT;
        return -1;
    }

    return s_rc;
}

static void _modbus_udp_free(modbus_t *ctx) {
    free(ctx->backend_data);
    free(ctx);
}

static const char* _modbus_udp_pi_getAddress(modbus_t *ctx)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return NULL;
    }

    if (ctx->backend == NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (ctx->backend->backend_type == _MODBUS_BACKEND_TYPE_UDP)
    {
        modbus_udp_pi_t *ctx_udp_pi = ctx->backend_data;
        if (ctx_udp_pi == NULL) {
            errno = EINVAL;
            return NULL;
        }
        return ctx_udp_pi->node;
    } else {
        errno = EINVAL;
        return NULL;
    }
}

static const char* _modbus_udp_getAddress(modbus_t *ctx)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return NULL;
    }

    if (ctx->backend == NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (ctx->backend->backend_type == _MODBUS_BACKEND_TYPE_UDP)
    {
        modbus_udp_t *ctx_udp = ctx->backend_data;
        if (ctx_udp == NULL) {
            errno = EINVAL;
            return NULL;
        }
        return ctx_udp->ip;
    }
    else {
        errno = EINVAL;
        return NULL;
    }
}

const modbus_backend_t _modbus_udp_backend = {
    _MODBUS_BACKEND_TYPE_UDP,
    _MODBUS_UDP_HEADER_LENGTH,
    _MODBUS_UDP_CHECKSUM_LENGTH,
    MODBUS_UDP_MAX_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_udp_build_request_basis,
    _modbus_udp_build_response_basis,
    _modbus_udp_prepare_response_tid,
    _modbus_udp_send_msg_pre,
    _modbus_udp_send,
    _modbus_udp_receive,
    _modbus_udp_recv,
    _modbus_udp_check_integrity,
    _modbus_udp_pre_check_confirmation,
    _modbus_udp_connect,
    _modbus_udp_close,
    _modbus_udp_flush,
    _modbus_udp_select,
    _modbus_udp_free,
    _modbus_udp_getAddress
};

const modbus_backend_t _modbus_udp_pi_backend = {
    _MODBUS_BACKEND_TYPE_UDP,
    _MODBUS_UDP_HEADER_LENGTH,
    _MODBUS_UDP_CHECKSUM_LENGTH,
    MODBUS_UDP_MAX_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_udp_build_request_basis,
    _modbus_udp_build_response_basis,
    _modbus_udp_prepare_response_tid,
    _modbus_udp_send_msg_pre,
    _modbus_udp_send,
    _modbus_udp_receive,
    _modbus_udp_recv,
    _modbus_udp_check_integrity,
    _modbus_udp_pre_check_confirmation,
    _modbus_udp_pi_connect,
    _modbus_udp_close,
    _modbus_udp_flush,
    _modbus_udp_select,
    _modbus_udp_free,
    _modbus_udp_pi_getAddress
};

modbus_t* modbus_new_udp(const char *ip, int port)
{
    modbus_t *ctx;
    modbus_udp_t *ctx_udp;
    size_t dest_size;
    size_t ret_size;

#if defined(OS_BSD)
    /* MSG_NOSIGNAL is unsupported on *BSD so we install an ignore
       handler for SIGPIPE. */
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        /* The debug flag can't be set here... */
        fprintf(stderr, "Could not install SIGPIPE handler.\n");
        return NULL;
    }
#endif

    ctx = (modbus_t *)malloc(sizeof(modbus_t));
    if (ctx == NULL) {
        return NULL;
    }
    _modbus_init_common(ctx);

    /* Could be changed after to reach a remote serial Modbus device */
    ctx->slave = MODBUS_UDP_SLAVE;

    ctx->backend = &_modbus_udp_backend;

    ctx->backend_data = (modbus_udp_t *)malloc(sizeof(modbus_udp_t));
    if (ctx->backend_data == NULL) {
        modbus_free(ctx);
        errno = ENOMEM;
        return NULL;
    }
    ctx_udp = (modbus_udp_t *)ctx->backend_data;

    if (ip != NULL) {
        dest_size = sizeof(char) * 16;
        ret_size = strlcpy(ctx_udp->ip, ip, dest_size);
        if (ret_size == 0) {
            fprintf(stderr, "The IP string is empty\n");
            modbus_free(ctx);
            errno = EINVAL;
            return NULL;
        }

        if (ret_size >= dest_size) {
            fprintf(stderr, "The IP string has been truncated\n");
            modbus_free(ctx);
            errno = EINVAL;
            return NULL;
        }
    } else {
        ctx_udp->ip[0] = '0';
    }
    ctx_udp->port = port;
    ctx_udp->t_id = 0;
    memset(&ctx_udp->addr, 0, sizeof(ctx_udp->addr));
    ctx_udp->addr_len = 0;

    return ctx;
}

modbus_t* modbus_new_udp_pi(const char *node, const char *service)
{
    modbus_t *ctx;
    modbus_udp_pi_t *ctx_udp_pi;
    size_t dest_size;
    size_t ret_size;

    ctx = (modbus_t *)malloc(sizeof(modbus_t));
    if (ctx == NULL) {
        return NULL;
    }
    _modbus_init_common(ctx);

    /* Could be changed after to reach a remote serial Modbus device */
    ctx->slave = MODBUS_UDP_SLAVE;

    ctx->backend = &_modbus_udp_pi_backend;

    ctx->backend_data = (modbus_udp_pi_t *)malloc(sizeof(modbus_udp_pi_t));
    if (ctx->backend_data == NULL) {
        modbus_free(ctx);
        errno = ENOMEM;
        return NULL;
    }
    ctx_udp_pi = (modbus_udp_pi_t *)ctx->backend_data;

    if (node == NULL) {
        /* The node argument can be empty to indicate any hosts */
        ctx_udp_pi->node[0] = 0;
    } else {
        dest_size = sizeof(char) * _MODBUS_UDP_PI_NODE_LENGTH;
        ret_size = strlcpy(ctx_udp_pi->node, node, dest_size);
        if (ret_size == 0) {
            fprintf(stderr, "The node string is empty\n");
            modbus_free(ctx);
            errno = EINVAL;
            return NULL;
        }

        if (ret_size >= dest_size) {
            fprintf(stderr, "The node string has been truncated\n");
            modbus_free(ctx);
            errno = EINVAL;
            return NULL;
        }
    }

    if (service != NULL) {
        dest_size = sizeof(char) * _MODBUS_UDP_PI_SERVICE_LENGTH;
        ret_size = strlcpy(ctx_udp_pi->service, service, dest_size);
    } else {
        /* Empty service is not allowed, error catched below. */
        ret_size = 0;
    }

    if (ret_size == 0) {
        fprintf(stderr, "The service string is empty\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    if (ret_size >= dest_size) {
        fprintf(stderr, "The service string has been truncated\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    ctx_udp_pi->t_id = 0;
    memset(&ctx_udp_pi->addr, 0, sizeof(ctx_udp_pi->addr));
    ctx_udp_pi->addr_len = 0;

    return ctx;
}
