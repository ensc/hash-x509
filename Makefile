MAKE_ORIG = ${MAKE} -f $(firstword ${MAKEFILE_LIST})

srcdir = $(dir $(firstword ${MAKEFILE_LIST}))
abs_srcdir = $(abspath ${srcdir})

VPATH = ${abs_srcdir}

PKG_CONFIG = pkg-config
INSTALL = install
INSTALL_BIN = ${INSTALL} -p -m 0755 -D

prefix = /usr/local
bindir = ${prefix}/bin

CFLAGS_openssl = $(shell ${PKG_CONFIG} --cflags libcrypto)
LIBS_openssl = $(shell ${PKG_CONFIG} --libs libcrypto)

CFLAGS  ?= -Wall -W -Werror -D_FORTIFY_SOURCE=2 -O2
LDFLAGS ?= -Wl,-as-needed

AM_CFLAGS = ${CFLAGS_openssl} -std=gnu99
LIBS = ${LIBS_openssl}

bin_PROGRAMS = \
	hash-x509 \
	chain-x509 \

hash-x509_SOURCES = \
	src/hash-x509.c

chain-x509_SOURCES = \
	src/chain-x509.c

all: ${bin_PROGRAMS}

hash-x509:	${hash-x509_SOURCES}
	${CC} ${AM_CFLAGS} ${CFLAGS} ${AM_LDFLAGS} ${LDFLAGS} $(filter %.c,$^) -o $@ ${LIBS}

chain-x509:	${chain-x509_SOURCES}
	${CC} ${AM_CFLAGS} ${CFLAGS} ${AM_LDFLAGS} ${LDFLAGS} $(filter %.c,$^) -o $@ ${LIBS}

check:	${bin_PROGRAMS} | test/.dirstamp
	${MAKE} -C test -I ${abs_srcdir}/test -f ${abs_srcdir}/test/Makefile check

clean:
	rm -f ${bin_PROGRAMS}

install:	${bin_PROGRAMS}
	${INSTALL_BIN} hash-x509  ${DESTDIR}${bindir}/hash-x509
	${INSTALL_BIN} chain-x509 ${DESTDIR}${bindir}/chain-x509

test/.dirstamp:
	mkdir -p ${@D}
	@touch $@
