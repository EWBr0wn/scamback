PROG = scam-back
CC = cc
CCFLAGS = -O2 -D_REENTRANT
CFLAGS = -I/usr/local/include/
LDFLAGS =  -L/usr/local/lib
LIBS = -lmilter -lresolv -pthread
SRC = scam-back.c util.c tcp.c
$(PROG): ${SRC}
		${CC} ${CCFLAGS} ${SRC} ${CFLAGS} ${LDFLAGS} ${LIBS} -o ${PROG}
clean:
	-rm -f $(PROG) *.o *.core
