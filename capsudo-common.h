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

#pragma once
#include <stddef.h>

enum capsudo_fieldtype {
	CAPSUDO_ARG = 1,
	CAPSUDO_ENV = 2,
	CAPSUDO_EXIT = 3,
	CAPSUDO_FD = 4,
	CAPSUDO_SESSION_TYPE = 5,
	CAPSUDO_END = 6,
};

enum capsudo_sessiontype {
	CAPSUDO_AUTO = 1,
	CAPSUDO_INTERACTIVE = 2,
	CAPSUDO_NONINTERACTIVE = 3,
};

struct capsudo_message {
	enum capsudo_fieldtype fieldtype;
	size_t length;
	char data[];
};
