/*
 * Copyright (c) 2024 Ariadne Conill <ariadne@ariadne.space>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#include "capsudo-common.h"

#pragma once

/* Fixed, host-stable wire header: u32le field type + u32le payload length. */
#define CAPSUDO_HEADER_SIZE 8

extern void capsudo_put_u16le(uint8_t *p, uint16_t v);
extern uint16_t capsudo_get_u16le(const uint8_t *p);
extern void capsudo_put_u32le(uint8_t *p, uint32_t v);
extern uint32_t capsudo_get_u32le(const uint8_t *p);

extern void capsudo_encode_header(uint8_t buf[CAPSUDO_HEADER_SIZE], uint32_t type, uint32_t len);
extern void capsudo_decode_header(const uint8_t buf[CAPSUDO_HEADER_SIZE], uint32_t *type, uint32_t *len);

extern bool write_message_bytes(int sockfd, enum capsudo_fieldtype fieldtype, const void *buf, size_t len);
extern bool write_message(int sockfd, enum capsudo_fieldtype fieldtype, const char *msgbuf);
extern bool write_u32_message(int sockfd, enum capsudo_fieldtype fieldtype, uint32_t msg);
extern bool read_message_header(int sockfd, uint32_t *out_type, uint32_t *out_len);
extern bool recv_exact(int sockfd, void *buf, size_t len);
extern int open_listener(const char *sockaddr, uid_t uid, gid_t gid, mode_t mode);
