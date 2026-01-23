CAPSUDO_DEFAULT_SOCK ?= /run/capsudo/default
PREFIX ?= /usr/local
CONFDIR ?= /etc
CFLAGS ?= -D_GNU_SOURCE -O2 -Wall -pedantic -std=gnu2x -ggdb3
PROGS := capsudo capsudod capsudod-pwauth

CAPSUDO_SRCS := capsudo.c capsudo-message.c
CAPSUDO_OBJS := ${CAPSUDO_SRCS:.c=.o}

CAPSUDOD_SRCS := capsudod.c capsudo-message.c capsudo-ownerspec.c
CAPSUDOD_OBJS := ${CAPSUDOD_SRCS:.c=.o}

CAPSUDOD_PWAUTH_SRCS := capsudod-pwauth.c capsudo-message.c capsudo-ownerspec.c
CAPSUDOD_PWAUTH_OBJS := ${CAPSUDOD_PWAUTH_SRCS:.c=.o}

CPPFLAGS += '-DCAPSUDO_DEFAULT_SOCK="${CAPSUDO_DEFAULT_SOCK}"'

all: ${PROGS}

capsudo: ${CAPSUDO_OBJS}
	${CC} -o $@ ${CAPSUDO_OBJS}

capsudod: ${CAPSUDOD_OBJS}
	${CC} -o $@ ${CAPSUDOD_OBJS}

capsudod-pwauth: ${CAPSUDOD_PWAUTH_OBJS}
	${CC} -o $@ ${CAPSUDOD_PWAUTH_OBJS} -lcrypt

clean:
	rm -f ${PROGS} ${CAPSUDO_OBJS} ${CAPSUDOD_OBJS}

INSTALL_OPENRC_FILES ?= false

install:
	install -Dm755 capsudo ${DESTDIR}${PREFIX}/bin/capsudo
	install -Dm755 capsudod ${DESTDIR}${PREFIX}/bin/capsudod
	install -Dm755 capsudod-pwauth ${DESTDIR}${PREFIX}/bin/capsudod-pwauth

	if ${INSTALL_OPENRC_FILES}; then \
		install -Dm755 dist/openrc/capsudo.initd ${DESTDIR}${CONFDIR}/init.d/capsudo; \
		install -Dm644 dist/openrc/capsudo.confd ${DESTDIR}${CONFDIR}/conf.d/capsudo; \
		ln -sf capsudo ${DESTDIR}${CONFDIR}/init.d/capsudo-pwauth; \
	fi
