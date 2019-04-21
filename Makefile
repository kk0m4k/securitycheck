#
# Makefile for secauditforunix
#

CC       = gcc
CFLAGS	 = -DLinux
#CFLAGS	 = -DSunOS
#CFLAGS	 = -DHPUX -Wall -static
#STATIC   = -static

SRCS   = secauditforunix.c util.o

OBJS   = secauditforunix.o util.o

all: secauditforunix
	@echo '*** stopping make secauditforunix ***'
	@exec make secauditforunix

secauditforunix:   secauditforunix.c util.c
	${CC} ${CFLAGS} -o $@ secauditforunix.c util.c
#	@strip $@

debug:   secauditforunix.c util.c
	${CC} -DDEBUG ${CFLAGS} -o secauditforunix secauditforunix.c util.c
#	@strip secauditforunix

clean:
	rm -f ${OBJS} core secauditforunix
