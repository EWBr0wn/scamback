/*
Copyright © 2004-2008 Eland Systems All Rights Reserved.

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

#ifdef SOLARIS
#include <sys/filio.h>
#endif

#include "tcp.h"

int
waitconnect(int sockfd, int timeout_msec)
{
  fd_set fd;
  fd_set errfd;
  struct timeval interval;
  int rc;

  /* now select() until we get connect or timeout */
  FD_ZERO(&fd);
  FD_SET(sockfd, &fd);

  FD_ZERO(&errfd);
  FD_SET(sockfd, &errfd);

  interval.tv_sec = timeout_msec/1000;
  timeout_msec -= interval.tv_sec*1000;

  interval.tv_usec = timeout_msec*1000;

  rc = select(sockfd+1, NULL, &fd, &errfd, &interval);
  if(-1 == rc)
    /* error, no connect here, try next */
    return -1;

  else if(0 == rc)
    /* timeout, no connect today */
    return 1;

  if(FD_ISSET(sockfd, &fd)) {
    /* error condition caught */
    return 2;
  }

  /* we have a connect! */
  return 0;
}

int
clientconn(int sockfd, struct in_addr addr, short int port, unsigned int timeout)
{
	struct sockaddr_in sa;
	int flags =1;
	int rc;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr.s_addr;
	sa.sin_port = htons(port);

	if (-1 == ioctl(sockfd, FIONBIO, &flags))
		return -1;

	rc = connect(sockfd, (struct sockaddr *)&sa, sizeof(sa));

	if(-1 == rc)
	{
		switch (errno)
		{
			case EINPROGRESS:
			case EWOULDBLOCK:
			case EINTR:
				rc = waitconnect(sockfd, timeout);
				break;

			case ECONNREFUSED:
			default:
				return -1;
		}
	}

	if (0 == rc)
	{
		int len = 0;
		int slen = sizeof(len);
		if ( -1 == getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void*)&len, &slen))
		{
			int err = errno;
			if ((0 == err) || (EISCONN == err))
			{
				rc = 0;
			} else
				rc = -1;
		}
	}
	return rc;
}

int
clientread(int sockfd, char** buffer, size_t buffersize, unsigned int timeout )
{
	int ret;
	fd_set readfd;
	struct timeval interval;
	int readbytes = 0;
	int flags = 0;
	const int BUFSIZE = 4096;

	interval.tv_sec = timeout;
    interval.tv_usec = 0;

	if (*buffer == NULL)
		return -1;

	if (sockfd < 0)
		return -1;

	do {
		FD_ZERO (&readfd);
		FD_SET (sockfd, &readfd);

		ret = select (sockfd + 1, &readfd, NULL, NULL, &interval);

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
				if(FD_ISSET(sockfd, &readfd))
				{
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
						interval.tv_sec = 0;
						interval.tv_usec = 100;
					}
					else if (ret < 0)
					{
						if (errno != EINTR)
							ret = -1;
					} else if (ret == 0)
					{
						ret = -1;
					}
				}
		}
	} while (ret != -1);

	return readbytes;
}

int
clientwrite(int sockfd, char* buffer, int len)
{
	int ret;
	fd_set fdw;
	struct timeval interval;
	int nwrite = 0;

	if (sockfd < 0)
		return -1;

	interval.tv_sec = 1;
    interval.tv_usec = 0;

	FD_ZERO( &fdw );
	FD_SET(sockfd, &fdw);
	ret = select(sockfd + 1, NULL, &fdw, NULL, &interval);

	if ((ret == -1) || (! FD_ISSET(sockfd, &fdw)))
	{
		return -1;
	}

	do {
		ret = write(sockfd, buffer+nwrite, len);
		if (ret != -1)
			nwrite += ret;

	} while ((( ret != -1) || (ret== -1 && errno == EINTR)) && (nwrite < len));

	if (nwrite != (int) len)
	{
		syslog( LOG_ERR, "clientwrite fail error %d", errno);
		return -1;
	}

	return 0;
}

