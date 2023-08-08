// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

/* size of stats map */
#define STATS_SIZE 1

/* position in stats map where we store generic counters */
#define GENERIC_STATS_INDEX 0

/* position in stats map where we store server_info */
#define SERVER_INFO_INDEX 0

/*
 * Currently, servers use TCP_HDR_OPT_KIND, but we'll be migrating them
 * to use TCP_SRV_HDR_OPT_KIND because we want the server and client to
 * use different OPTs.
 */
#define TCP_SRV_HDR_OPT_KIND 0xB6

/* Reserved hdr-opt-value for this case.
 * Picked random unused value from IANA TCP Option Kind Numbers
 */
#define TCP_HDR_OPT_KIND 0xB7

/*
 * We don't insert the TPR opt on the server side if this opt is present
 * in the client's SYN
 */
#define KDE_CLT_TCP_HDR_OPT_KIND 0xB8

/* 4 bytes len for the server-id in TCP_HDR_OPT + KIND and LEN */
#define TCP_HDR_OPT_LEN 6

/* For consistent handling of success vs failues */
#define CG_OK 1
#define CG_ERR 0

/* value to represent the 'server' side */
#define SERVER_MODE 1
#define CLIENT_MODE 2

/* Server info map has only 1 item */
#define SERVER_INFO_MAP_SIZE 1

#define TCPHDR_SYN 0x02
#define TCPHDR_ACK 0x10
#define TCPHDR_SYNACK (TCPHDR_SYN | TCPHDR_ACK)

#define NO_FLAGS 0
#define SUCCESS 0
#define PASS -1
