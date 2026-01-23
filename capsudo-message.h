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

extern bool write_raw_message(int sockfd, struct capsudo_message *msg);
extern bool write_message(int sockfd, enum capsudo_fieldtype fieldtype, const char *msgbuf);
extern bool write_u32_message(int sockfd, enum capsudo_fieldtype fieldtype, uint32_t msg);
extern bool recv_exact(int sockfd, void *buf, size_t len);
extern int open_listener(const char *sockaddr, uid_t uid, gid_t gid, mode_t mode);
