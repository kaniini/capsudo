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

#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "capsudo-common.h"
#include "capsudo-message.h"

/*
 * The wire format is host-stable: a fixed 8-byte header (u32le field type +
 * u32le length) followed by the payload, with all integers little-endian and no
 * native struct/padding dependence. It is byte-compatible with the Rust
 * implementation (capsudo-rs). The in-memory `struct capsudo_message` is never
 * read or written raw; it is only a convenience container.
 */

void capsudo_put_u16le(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t) v;
	p[1] = (uint8_t) (v >> 8);
}

uint16_t capsudo_get_u16le(const uint8_t *p)
{
	return (uint16_t) (p[0] | ((uint16_t) p[1] << 8));
}

void capsudo_put_u32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t) v;
	p[1] = (uint8_t) (v >> 8);
	p[2] = (uint8_t) (v >> 16);
	p[3] = (uint8_t) (v >> 24);
}

uint32_t capsudo_get_u32le(const uint8_t *p)
{
	return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
	       ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

void capsudo_encode_header(uint8_t buf[CAPSUDO_HEADER_SIZE], uint32_t type, uint32_t len)
{
	capsudo_put_u32le(buf, type);
	capsudo_put_u32le(buf + 4, len);
}

void capsudo_decode_header(const uint8_t buf[CAPSUDO_HEADER_SIZE], uint32_t *type, uint32_t *len)
{
	*type = capsudo_get_u32le(buf);
	*len = capsudo_get_u32le(buf + 4);
}

static bool write_all(int sockfd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len)
	{
		ssize_t n = write(sockfd, p, len);

		if (n < 0)
		{
			if (errno == EINTR)
				continue;

			return false;
		}

		if (n == 0)
			return false;

		p += (size_t) n;
		len -= (size_t) n;
	}

	return true;
}

bool write_message_bytes(int sockfd, enum capsudo_fieldtype fieldtype, const void *buf, size_t len)
{
	uint8_t hdr[CAPSUDO_HEADER_SIZE];

	capsudo_encode_header(hdr, (uint32_t) fieldtype, (uint32_t) len);

	if (!write_all(sockfd, hdr, sizeof hdr))
		return false;

	if (len && !write_all(sockfd, buf, len))
		return false;

	return true;
}

bool write_message(int sockfd, enum capsudo_fieldtype fieldtype, const char *msgbuf)
{
	/* Strings travel without a trailing NUL; the receiver re-terminates. */
	return write_message_bytes(sockfd, fieldtype, msgbuf, strlen(msgbuf));
}

bool write_u32_message(int sockfd, enum capsudo_fieldtype fieldtype, uint32_t msg)
{
	uint8_t buf[4];

	capsudo_put_u32le(buf, msg);
	return write_message_bytes(sockfd, fieldtype, buf, sizeof buf);
}

bool read_message_header(int sockfd, uint32_t *out_type, uint32_t *out_len)
{
	uint8_t hdr[CAPSUDO_HEADER_SIZE];

	if (!recv_exact(sockfd, hdr, sizeof hdr))
		return false;

	capsudo_decode_header(hdr, out_type, out_len);
	return true;
}

bool recv_exact(int fd, void *buf, size_t len)
{
	char *p = (char *)buf;

	while (len)
	{
		ssize_t n = read(fd, p, len);

		if (n == 0)
			return false;

		if (n < 0)
		{
			if (errno == EINTR)
				continue;

			return false;
		}

		p += (size_t)n;
		len -= (size_t)n;
	}

	return true;
}

int open_listener(const char *sockaddr, uid_t uid, gid_t gid, mode_t mode)
{
	int sockfd;
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};

	unlink(sockaddr);
	strlcpy(addr.sun_path, sockaddr, sizeof(addr.sun_path));

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0)
		err(EXIT_FAILURE, "opening listener socket %s", sockaddr);

	if (bind(sockfd, (struct sockaddr *) &addr, sizeof addr) < 0)
		err(EXIT_FAILURE, "binding listener socket to %s", sockaddr);

	if (uid != -1 || gid != -1)
		if (chown(sockaddr, uid, gid) < 0)
			err(EXIT_FAILURE, "setting listener socket ownership to %u:%u", uid, gid);

	if (chmod(sockaddr, mode) < 0)
		err(EXIT_FAILURE, "setting listener socket permissions to %o", mode);

	if (listen(sockfd, 50) < 0)
		err(EXIT_FAILURE, "listening on socket %s", sockaddr);

	return sockfd;
}
