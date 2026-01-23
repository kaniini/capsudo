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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
