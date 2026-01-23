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

bool write_raw_message(int sockfd, struct capsudo_message *msg)
{
	size_t nwritten, xwritten;

	xwritten = sizeof(struct capsudo_message) + msg->length;
	if ((nwritten = write(sockfd, msg, xwritten)) != xwritten)
	{
		close(sockfd);
		err(EXIT_FAILURE, "failed to write %zu bytes to capsudo daemon, wrote %zu instead", xwritten, nwritten);
	}

	return true;
}

bool write_message(int sockfd, enum capsudo_fieldtype fieldtype, const char *msgbuf)
{
	struct capsudo_message *envmsg = alloca(sizeof(struct capsudo_message) + strlen(msgbuf) + 1);

	envmsg->fieldtype = fieldtype;
	envmsg->length = strlen(msgbuf) + 1;
	strlcpy(envmsg->data, msgbuf, envmsg->length);

	return write_raw_message(sockfd, envmsg);
}

bool write_u32_message(int sockfd, enum capsudo_fieldtype fieldtype, uint32_t msg)
{
	struct capsudo_message *envmsg = alloca(sizeof(struct capsudo_message) + sizeof(uint32_t));

	envmsg->fieldtype = fieldtype;
	envmsg->length = sizeof(uint32_t);
	memcpy(envmsg->data, &msg, sizeof(uint32_t));

	return write_raw_message(sockfd, envmsg);
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
