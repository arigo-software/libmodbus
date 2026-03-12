/*
 * Copyright © 2001-2013 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#ifndef MODBUS_UDP_PRIVATE_H
#define MODBUS_UDP_PRIVATE_H

/* UDP uses the same MBAP header as TCP */
#define _MODBUS_UDP_HEADER_LENGTH      7
#define _MODBUS_UDP_PRESET_REQ_LENGTH 12
#define _MODBUS_UDP_PRESET_RSP_LENGTH  8

#define _MODBUS_UDP_CHECKSUM_LENGTH    0

/* Maximum UDP payload size - conservative value for wide compatibility */
#define MODBUS_UDP_MAX_ADU_LENGTH     512

typedef struct _modbus_udp {
    /* Transaction identifier */
    uint16_t t_id;
    /* UDP port */
    int port;
    /* IP address */
    char ip[16];
    /* Remote address for server responses */
    struct sockaddr_in addr;
    socklen_t addr_len;
} modbus_udp_t;

#define _MODBUS_UDP_PI_NODE_LENGTH    1025
#define _MODBUS_UDP_PI_SERVICE_LENGTH   32

typedef struct _modbus_udp_pi {
    /* Transaction identifier */
    uint16_t t_id;
    /* UDP port */
    int port;
    /* Node */
    char node[_MODBUS_UDP_PI_NODE_LENGTH];
    /* Service */
    char service[_MODBUS_UDP_PI_SERVICE_LENGTH];
    /* Remote address for server responses */
    struct sockaddr_storage addr;
    socklen_t addr_len;
} modbus_udp_pi_t;

#endif /* MODBUS_UDP_PRIVATE_H */
