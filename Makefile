PREFIX ?= /usr/local
CFLAGS ?= -D_GNU_SOURCE -O2 -Wall -pedantic -std=gnu2x -ggdb3
PROGS := capsudo capsudod

CAPSUDO_SRCS := capsudo.c capsudo-message.c
CAPSUDO_OBJS := ${CAPSUDO_SRCS:.c=.o}

CAPSUDOD_SRCS := capsudod.c capsudo-message.c
CAPSUDOD_OBJS := ${CAPSUDOD_SRCS:.c=.o}

all: ${PROGS}

capsudo: ${CAPSUDO_OBJS}
	${CC} -o $@ ${CAPSUDO_OBJS}

capsudod: ${CAPSUDOD_OBJS}
	${CC} -o $@ ${CAPSUDOD_OBJS}

clean:
	rm -f ${PROGS} ${CAPSUDO_OBJS} ${CAPSUDOD_OBJS}

install:
	install -Dm755 capsudo ${DESTDIR}${PREFIX}/bin/capsudo
	install -Dm755 capsudod ${DESTDIR}${PREFIX}/bin/capsudod
