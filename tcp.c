/*
Copyright © 2004-2009 Eland Systems All Rights Reserved.

   1. Redistribution and use in source and binary forms must retain the above
   copyright notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   3. All advertising materials mentioning features or use of this software
	must display the following acknowledgement:
         This product includes software developed by Eland Systems.

   4. The name of Eland Systems may not be used to endorse or promote products
   derived from this software without specific prior written permission.

   Author scam+back@elandsys.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sysexits.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <syslog.h>

#ifdef HAVEPOLL
#include <poll.h>
#endif

#ifdef SOLARIS
#include <sys/filio.h>
#endif

#include "tcp.h"

#ifndef howmany
#define  howmany(x,y)    (((x)+((y)-1))/(y))
#endif

#ifdef HAVEPOLL
int
waitpoll(int fd, int events, int timeout_msec)
{
    struct pollfd pfd[1];
	int nfds;

    pfd[0].fd = fd;
    pfd[0].events = events;

	nfds = poll(pfd, 1, timeout_msec);

    if (nfds == -1 || (pfd[0].revents & (POLLERR|POLLHUP|POLLNVAL)))
		return nfds ;

	if (nfds == 0)
		return -2;

	return 0;
}

#else

int
waitconnect(int sockfd, int timeout_msec)
{
  fd_set *fds;
  struct timeval interval;
  int rc, fdsz, sval;
  socklen_t slen;

  interval.tv_sec = timeout_msec/1000;
  timeout_msec -= interval.tv_sec*1000;

  interval.tv_usec = timeout_msec*1000;

  fdsz = howmany(sockfd+1, NFDBITS) * sizeof(fd_mask);
  fds = (fd_set *) malloc(fdsz);
  FD_ZERO(fds);
  FD_SET(sockfd, fds);

  rc = select(sockfd+1, NULL, fds, NULL, &interval);

  switch (rc)
  {
	  case 0:
		/* timeout, no connection */
		errno = ETIMEDOUT;
	  case -1:
		  return -1;
	      break;

	  case 1:
		sval = 0;
	    slen = sizeof(sval);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sval, &slen) == -1)
		{
			free(fds );
			return -1;
		}
		if (sval != 0)
		{
			errno = sval;
			free(fds );
		    return -1;
		}
		return 0;

		default:
			/* any other condition */
			free(fds );
			return -1;
	}
  free(fds );
  return 0;
}

#endif /* HAVEPOLL */

int
clientconn(int sockfd, struct in_addr addr, short int port, unsigned int timeout)
{
	struct sockaddr_in sa;
	int rc;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr.s_addr;
	sa.sin_port = htons(port);

#if defined(O_NONBLOCK)
	if (-1 == fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK))
		return -1;
#else
	rc = 1;
	if (-1 == ioctl(sockfd, FIONBIO, &rc))
		return -1;
#endif
	rc = connect(sockfd, (struct sockaddr *)&sa, sizeof(sa));

	if (0 == rc)
		return 0;

	if (errno != EINPROGRESS)
		return -1;

#ifdef HAVEPOLL
	rc = waitpoll( sockfd, POLLOUT|POLLIN, timeout);
	if (rc == -2)
	{
		errno = ETIMEDOUT;
	} else {
		int er = -1;
		socklen_t l = sizeof(er);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char *)&er, &l) < 0)
		{
			return -2;
		}
		if (er ==  ECONNREFUSED)
		{
			errno = ECONNREFUSED;
			rc = -1;
		}
	}
#else
	rc = waitconnect(sockfd, timeout);
#endif /* HAVEPOLL */

	return rc;
}

int
clientread(int sockfd, char** buffer, size_t buffersize, unsigned int timeout )
{
	int ret;
	int readbytes = 0;
	int flags = 0;
	const int BUFSIZE = 4096;
#ifdef HAVEPOLL
	int nfds;

	timeout = timeout * 1000;
#else
	fd_set readfd;
	struct timeval interval;

	interval.tv_sec = timeout;
    interval.tv_usec = 0;
#endif

	if (*buffer == NULL)
		return -1;

	if (sockfd < 0)
		return -1;

	do {
#ifdef HAVEPOLL
		nfds = waitpoll( sockfd, POLLIN, timeout);
		if (nfds == 0)
			ret = 1;
		else if (nfds == -2)
			ret = 0;
		else
			ret = -1;
#else
		FD_ZERO (&readfd);
		FD_SET (sockfd, &readfd);

		ret = select (sockfd + 1, &readfd, NULL, NULL, &interval);
#endif /* HAVEPOLL */
		switch(ret)
		{
			case -1:
				if (errno != EINTR)
				{
					syslog( LOG_ERR, "clientread fail error %d on fd %d", errno, sockfd);
					/* ret = -1; */
					return -1;
				}
				break;

			case 0:
				ret = -1;
				break;

			default:
#ifndef HAVEPOLL
				if(FD_ISSET(sockfd, &readfd))
				{
#endif
					if (readbytes == buffersize)
					{
						char *p;

						if ((p = realloc(*buffer, buffersize + BUFSIZE)) == NULL)
						{
							ret = -1;
							break;
						}
						*buffer = p;
						buffersize += BUFSIZE;
					}
					ret = recv( sockfd, *buffer + readbytes, buffersize - readbytes, flags);
					if (ret > 0)
					{
						readbytes += ret;
#ifdef HAVEPOLL
						timeout = 100;
#else
						interval.tv_sec = 0;
						interval.tv_usec = 100;
#endif
					}
					else if (ret < 0)
					{
						if (errno != EINTR)
							ret = -1;
					} else if (ret == 0)
					{
						ret = -1;
					}
#ifndef HAVEPOLL
				}
#endif
		}
	} while (ret != -1);

	return readbytes;
}

int
clientwrite(int sockfd, char* buffer, int len)
{
	int ret;
	int nwrite = 0;
#ifndef HAVEPOLL
	fd_set fdw;
	struct timeval interval;
#endif
	if (sockfd < 0)
		return -1;

#ifdef HAVEPOLL
	ret = waitpoll( sockfd, POLLOUT, 1000);
	if (ret != 0)
		return -1;
#else
	interval.tv_sec = 1;
    interval.tv_usec = 0;

	FD_ZERO( &fdw );
	FD_SET(sockfd, &fdw);
	ret = select(sockfd + 1, NULL, &fdw, NULL, &interval);

	if ((ret == -1) || (! FD_ISSET(sockfd, &fdw)))
	{
		return -1;
	}
#endif /* HAVEPOLL */

	do {
		ret = write(sockfd, buffer+nwrite, len - nwrite);
		if (ret != -1)
			nwrite += ret;
		else
			if (errno == EAGAIN)
				ret = 0;

	} while ((( ret != -1) || (ret== -1 && errno == EINTR)) && (nwrite < len));

	if (nwrite != (int) len)
	{
		syslog( LOG_ERR, "clientwrite fail error %d", errno);
		return -1;
	}

	return nwrite;
}
