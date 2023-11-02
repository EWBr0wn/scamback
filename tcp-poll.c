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
#include <dirent.h>

#ifdef _HAVE_POLL
#include <poll.h>
#endif

#ifndef TCPDEBUGGING
#include <syslog.h>
#endif

#include "tcp.h"

/* No howmany under freebsd */
#  ifndef       howmany
#       define  howmany(x,y)    (((x)+((y)-1))/(y))
#  endif

#ifdef _RIPMIME
#include "ripmime/mime.h"
#include "ripmime/logger.h"
#endif

#ifdef TCPDEBUGGING
struct fprotres {
	char version[16];
	char engine[16];
	char program[16];
	char filename[PATH_MAX];
	char virname[256];
	char type[256];
	int	code;
	int	msgnum;
	char	message[256];
	int	accuracy;
	int	encrypted;
};
#endif

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

  if(FD_ISSET(sockfd, &errfd)) {
    /* error condition caught */
    return 2;
  }

  /* we have a connect! */
  return 0;
}

int
clientconn(int sockfd, short int port)
{
	struct sockaddr_in sa;
	int flags =1;
	int rc;
	int timeout = 1500;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");
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
#ifdef TCPDEBUGGING
				fprintf( stderr, "no server on %d\n", port);
#else
				syslog(LOG_ERR, "no server on %d\n", port);
#endif
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
clientconnb(int sockfd, char* buffer)
{
	struct sockaddr_in sa;
	int flags =1;
	int rc;
	int timeout = 1500;
	int port = 25;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(buffer);
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
#ifdef TCPDEBUGGING
				fprintf( stderr, "no server on %d\n", port);
#else
				syslog(LOG_ERR, "no server on %d\n", port);
#endif
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
clientread(int sockfd, char** buffer, size_t buffersize, int timeout )
{
	int ret;
	fd_set *readfd;
	int max = sockfd;
	struct timeval interval;
	int readbytes = 0;
	int flags = 0;
	const int BUFSIZE = 4096;
	int loopcnt = 0;
	struct timeval gnow;
	struct timeval now;
	struct timezone tz;
#if _HAVE_POLL
	struct pollfd pfd[1];
#endif

	interval.tv_sec = timeout;
    interval.tv_usec = 0;

	if (*buffer == NULL)
		return -1;

	gettimeofday(&gnow, &tz);
#ifdef _HAVE_POLL
	pfd[0].fd = sockfd;
	pfd[0].events = POLLIN;

	while (pfd[0].fd != -1)
	{
		if ((ret = poll(pfd, 1, 30)) < 0)
		{
			syslog( LOG_ERR, "clientpoll fail %d", errno);
			break;
		}

		if (ret == 0)
			break;

		if (pfd[0].revents & POLLIN)
		{
				if ((ret = read(sockfd, *buffer+readbytes, buffersize - readbytes)) < 0)
					break;
				else
					if (ret == 0)
					{
						pfd[0].fd = -1;
						pfd[0].events = 0;
					} else {
						readbytes += ret;
						if (readbytes == buffersize)
						{
							buffersize += BUFSIZE;
							*buffer = (char *) realloc(*buffer, buffersize);
						}
					}
		}

	}
#else
	readfd = (fd_set *)calloc(howmany(max+1, NFDBITS), sizeof(fd_mask));
	if (readfd == NULL)
	{
		return -1;
	}

	do {
		FD_ZERO (readfd);
		FD_SET (sockfd, readfd);
		ret = select (sockfd + 1, readfd, NULL, NULL, &interval);

		switch(ret)
		{
			case -1:
				if (errno != EINTR)
				{
#ifdef TCPDEBUGGING
					fprintf( stderr, "clientread fail %d", errno);
#else
					syslog( LOG_ERR, "clientread fail %d", errno);
#endif
					ret = -1;
				}
				break;

			case 0:
				/* let us wait timeout secs if we have to received any data */
				loopcnt++;
				ret = -1;
				break;

			default:
			if(FD_ISSET(sockfd, readfd))
			{
				if (readbytes == buffersize)
				{
					buffersize += BUFSIZE;
					*buffer = (char *) realloc(*buffer, buffersize);

#ifdef TCPDEBUGGING
				fprintf( stdout, "\nalloc bufsize %d\n", buffersize);
#endif
				}
				ret = recv( sockfd, *buffer + readbytes, buffersize - readbytes, flags);
				if (ret > 0)
				{
					readbytes += ret;
					//ret = -1;
#ifdef TCPDEBUGGING
					fprintf( stdout, "read %d return %d\n", readbytes, ret);
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
			}
		}
		if (loopcnt == 10)
		{
#ifdef TCPDEBUGGING
			gettimeofday(&now, &tz);
			fprintf( stderr, "socket readtimeout read: %d after %d secs\n", readbytes, now.tv_sec - gnow.tv_sec);
#else
			gettimeofday(&now, &tz);
			syslog( LOG_ERR, "socket timeout read: %d after %d secs", readbytes, (int)(now.tv_sec - gnow.tv_sec));
#endif
			ret = -1;
		}
	} while (ret != -1);
#endif
	free(readfd );

	return readbytes;
}

int
clientwrite(int sockfd, char* buffer, int len)
{
	int ret;
	fd_set *fdsr;
	int max = sockfd;
	struct timeval interval;
	int nwrite = 0;

	interval.tv_sec = 1;
    interval.tv_usec = 0;

	fdsr = (fd_set *)calloc(howmany(max+1, NFDBITS), sizeof(fd_mask));
	if (fdsr == NULL)
	{
		return -1;
	}

	FD_ZERO( fdsr );
	FD_SET(sockfd, fdsr);
	ret = select(max + 1, NULL, fdsr, NULL, &interval);

	if (ret == -1)
	{
		free(fdsr);
		return -1;
	}

	do {
		ret = write(sockfd, buffer+nwrite, len);
		if (ret != -1)
			nwrite += ret;

	} while ((( ret != -1) || (ret== -1 && errno == EINTR)) && (nwrite < len));

	if (nwrite != (int) len)
	{
#ifdef TCPDEBUGGING
		fprintf( stderr, "request failed\n");
#else
		syslog( LOG_ERR, "clientread fail %d", errno);
#endif
		free(fdsr);
		return -1;
	} else {
#ifdef TCPDEBUGGING
		fprintf( stdout, "sent request\n");
#endif
	}
	free(fdsr);

	return 0;
}


#ifdef TCPDEBUGGING
static  char* smgetline(const char *line,  int start, int end)
{
	const char *p, *q;
	int len = 0;
	int skip = 0;
	char *dst = NULL;

	p = ( char *) line;

	p = (p += start);
	while ((*p == '\n') || (*p == '\r') || (*p == ' ') || (*p == '\t'))
	{
		p++;
		skip++;
	}

	q = p;

	while ((*p) && (len + start < end))
	{
		if (*p == '\n')
		{
			break;
		}
		//fprintf( stdout,"%c", *p);
		len++;
		p++;

	}

	//fprintf( stdout,"LINE:%s %d  %d\n", line, start, len);
	dst = malloc(len +1);
	memcpy( dst, q, len);
	dst[len] = '\0';
	return (dst);

}

int
checkback( char* addr)
{
	int sockfd;
	int rc;
	char *buffer;
	int lenbuf;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	rc = clientconnb( sockfd, "10.0.0.2");
	if ( 0 != rc)
	{
		close(sockfd);
		return -1;
	}

	buffer = malloc(1024);
	rc = clientread( sockfd, &buffer, 1023, 5);
	buffer[rc] = 0;
	fprintf( stdout, "%s %d\n", buffer, rc);
	if (rc < 5)
	{
		close(sockfd);
		return -1;
	}

	if (strncmp(buffer, "220", 3) != 0)
	{
		close(sockfd);
		return -1;
	}

	snprintf( buffer, 1024, "HELO localhost\r\n");
	lenbuf = strlen(buffer);
	rc = clientwrite( sockfd, buffer, lenbuf);

	if ( 0 != rc)
	{
		close(sockfd);
		return -1;
	}

	rc = clientread( sockfd, &buffer, 1023, 2 );
	buffer[rc] = 0;

	if (rc < 5)
	{
		close(sockfd);
		return -1;
	}

	if (strncmp(buffer, "250", 3) != 0)
	{
		close(sockfd);
		return -1;
	}

	snprintf( buffer, 1023, "MAIL FROM:<postmaster@localhost>\r\n");
	lenbuf = strlen(buffer);
	rc = clientwrite( sockfd, buffer, lenbuf);

	if ( 0 != rc)
	{
		close(sockfd);
		return -1;
	}

	rc = clientread( sockfd, &buffer, 1023 , 2);
	buffer[rc] = 0;

	if (rc < 5)
	{
		close(sockfd);
		return -1;
	}

	if (strncmp(buffer, "250", 3) != 0)
	{
		close(sockfd);
		return -1;
	}

	snprintf( buffer, 1023, "RCPT TO:<%s>\r\n", addr);
	lenbuf = strlen(buffer);
	rc = clientwrite( sockfd, buffer, lenbuf);

	if ( 0 != rc)
	{
		close(sockfd);
		return -1;
	}

	rc = clientread( sockfd, &buffer, 1023 , 2);
	buffer[rc] = 0;

	if (rc < 5)
	{
		close(sockfd);
		return -1;
	}

	if (strncmp(buffer, "250", 3) != 0)
	{
		close(sockfd);
		return -1;
	}

	snprintf( buffer, 1023, "RSET\r\n");
	lenbuf = strlen(buffer);
	rc = clientwrite( sockfd, buffer, lenbuf);

	if ( 0 != rc)
	{
		close(sockfd);
		return -1;
	}

	rc = clientread( sockfd, &buffer, 1023, 2 );
	buffer[rc] = 0;

	if (rc < 5)
	{
		close(sockfd);
		return -1;
	}

	if (strncmp(buffer, "250", 3) != 0)
	{
		close(sockfd);
		return -1;
	}

	snprintf( buffer, 1023, "QUIT\r\n");
	lenbuf = strlen(buffer);
	rc = clientwrite( sockfd, buffer, lenbuf);

	if ( 0 != rc)
	{
		close(sockfd);
		return -1;
	}

	rc = clientread( sockfd, &buffer, 1023, 2 );
	buffer[rc] = 0;

	if (rc < 5)
	{
		close(sockfd);
		return -1;
	}

	close(sockfd);

	return 0;
}

int
virscan(char* filename, char* id, struct fprotres *fpresult)
{
	int sockfd;
	int rc;
	u_char buffer[PATH_MAX + 64];
	char *buf = NULL;
	size_t bufsize =  4096;
	int avport = 10200;

	int i;
	int code = 0;
	u_char *p;
	int stage;
	int httpcode = 0;
	size_t start;
	int lenp;

	for (i = 0; i < 5; i++)
	{
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		rc = clientconn( sockfd, avport);
		if ( -1 == rc)
		{
			close(sockfd);
			avport++;
			if (avport > 10204)
				avport = 10200;
		} else
			break;
	}

	if ( 0 != rc )
	{
		return -1;
	}

#ifdef TCPDEBUGGING
	fprintf( stdout, "connected\n");
#endif
	snprintf( buffer, sizeof(buffer), "GET %s?-id=%s HTTP/1.0\r\n\r\n", filename, id);
	lenp = strlen(buffer);
	rc = clientwrite( sockfd, buffer, lenp);
#ifdef TCPDEBUGGING
		fprintf( stdout, "write code %d\n", rc);
#endif
	if (rc > 0)
	{
		buf = malloc(bufsize);
		rc = clientread( sockfd, &buf, bufsize, 5 );
		buf[rc] = 0;
#ifdef TCPDEBUGGING
		//fprintf( stdout, "read %s \nreadall %d\n", buf, rc);
		//free(buf);
#endif
	}

	close(sockfd);
	sockfd = -1;

	if (rc > 0)
	{
		bzero((void *) fpresult, sizeof(struct fprotres));

		start = 0;
		stage = 0;

		while (start < rc)
		{
			p = NULL;
			p = smgetline(buf, start, rc);

			if (p) {
				//fprintf( stdout,"OUTPUT:%s END %04d\n", p, start);
				lenp = strlen(p);
				start += lenp + 1;
				if ((lenp > 5) && (lenp < 256))
					switch (stage)
					{
						case 0:
							if (1 == sscanf ( p, "HTTP/1.0 %d Ok", &httpcode))
							{
								stage = 1;
								if (httpcode != 200)
								{
									start = rc;
									code = -3;
								}
							}
							break;

						case 1:
							if (3 == sscanf ( p, "<fprot-results version=\"%[0-9.]\" engine=\"%[0-9.]\" program=\"%[0-9.]\"", fpresult->version, fpresult->engine, fpresult->program))
							{
								stage = 2;
							}
							break;

						case 2:
							if (1 != sscanf ( p, "<filename>%[^<]", fpresult->filename))
									if (1 != sscanf ( p, "<name>%[^<]", fpresult->virname))
										if (1 != sscanf ( p, "<detected type=\"%[^\"]", fpresult->type))
											if (1 != sscanf ( p, "<accuracy>%d", &fpresult->accuracy))
												if (1 != sscanf ( p, "<summary code=\"%d", &fpresult->code))
													if (2 != sscanf ( p, "<message num=\"%d\">%[^<]", &fpresult->msgnum, fpresult->message))
														if (1 == sscanf ( p, "<encrypted>%[^<]", buffer))
															fpresult->encrypted = 1;
						break;
				}
				free(p);
			} else
				break;
		}
#ifdef TCPDEBUGGING
		fprintf( stdout, "%s: %s %s %s %s\n", id, fpresult->filename, fpresult->virname, fpresult->type, fpresult->message);
		fprintf( stdout, "%s: code %d\n", id, fpresult->code);
		fprintf( stdout, "%s: accuracy %d\n", id, fpresult->accuracy);
#endif
	}
	else if (rc < 0)
	{
		//syslog (LOG_ERR, "%s: cannot read request from f-prot", qid);
		code = -2;
	}
	if (buf)
		free( buf);

	if (fpresult->code != 0)
		code = fpresult->code;

	return code;
}
#endif

#ifdef TCPDEBUGGING
void blah()
{
	struct fprotres *scanres;

	scanres = malloc(sizeof(struct fprotres));
	if (scanres == NULL)
		return;

	virscan("/home/sm/scam/av/special.vir", "3", scanres);
	fprintf(stdout, "\n scanres %s %s %d\n", scanres->version, scanres->type, scanres->code);
	free (scanres);
	return;
}

int
main(int argc, char *argv[])
{
	int ret;
	char *inputfile;
    unsigned char *dir;
	unsigned char *r;
	DIR *d;
	struct dirent *dentry;
	struct stat st;
	char fname[PATH_MAX];
	int start = 1;

	int hell;

	/*
	virscan("/home/sm/scam/filter/virus/PRODUCTS.LZH", "1");
	virscan("/home/sm/scam/filter/virus/noboundary.txt", "2");
	virscan("/home/sm/scam/filter/virus/message_.zip", "3");
	*/

	checkback("sm@esl");
	return 0;
	for (hell = 0; hell < 1; hell++)
	{
		blah();
		/*
		MIME_init();
		LOGGER_set_output_mode (_LOGGER_STDERR);
		MIME_set_uniquenames (1);
		MIME_set_paranoid (1);
		MIME_set_header_longsearch(1);
		MIME_set_renamemethod (_MIME_RENAME_METHOD_INFIX);
		MIMEH_set_outputdir(dir);
		ret = MIME_unpack(dir, inputfile , 0);
		fprintf( stdout, "ripmime %d\n", ret);
		MIME_close ();
		*/
		d = opendir(dir);
		if (d)
		{
			while (( dentry = readdir(d)) != NULL)
			{
				/*
				if ((!strcmp(dentry->d_name, ".")) || (!strcmp(dentry->d_name, "..")))
					continue;
				*/

					snprintf( fname, sizeof(fname), "%s/%s", dir, dentry->d_name);
				// todo set an error here to avoid not scanning
					if (stat(fname, &st) != 0)
						break;

					if (!S_ISDIR(st.st_mode))
					{
						//virscan(fname, "4", scanres);
					}

					//fprintf( stdout, "%s\n", dentry->d_name);

			}
			(void) closedir(d);
		}
		d = opendir(dir);
		if (d)
		{
			while (( dentry = readdir(d)) != NULL)
			{
					snprintf( fname, sizeof(fname), "%s/%s", dir, dentry->d_name);
					if (stat(fname, &st) != 0)
						break;

					if (!S_ISDIR(st.st_mode))
					{
						fprintf( stdout, "unlink %s\n", dentry->d_name);
						unlink(fname);
					}


			}
			(void) closedir(d);
		}
	}
	//virscan("/home/sm/virus/mbox", "4");
	return 0;
}
#endif
