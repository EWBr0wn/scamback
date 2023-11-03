/*
Copyright © 2006-2007 Eland Systems All Rights Reserved.

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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sysexits.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <syslog.h>

#include <pthread.h>

#include "libmilter/mfapi.h"

#ifndef LINUX
#ifdef SOLARIS
#include "queue.h"
#else
#include <sys/queue.h>
#endif
#else
#include "queue.h"
#endif

#include "lock.h"
#include "tcp.h"
#include "util.h"

#define PIDFILE "/var/spool/scam/scam-back.pid"
#define MLFIPRIV	((struct mlfiPriv *) smfi_getpriv(ctx))

#define LINELENGTH 1024
#define SCAMCONF "/etc/mail/scam.conf"
#define RCPTREJTEXT " User unknown"
#define TEMPFAILTEXT "Internal error"

#define VERSION "1.3.1"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#ifdef USEMAILERTABLE
#define MAILERTABLE "/etc/mail/mailertable"
#endif

#define MAXSMTPWAIT 5
#define RECVBUFLEN	1024

struct backent {
	char	*rcptaddr;
	int resp;
	struct timeval tv;
	TAILQ_ENTRY(backent)	backentries;
};

pthread_rwlock_t back_lock;

TAILQ_HEAD(backlist, backent);
struct backlist backhead;

struct doment {
	char	*domain;
	SLIST_ENTRY(doment)	domentries;
};

SLIST_HEAD(, doment) domlist;

#ifdef BITBUCKET
struct entry {
	char	*c;
	SLIST_ENTRY(entry)	entries;
};
#endif

static int backvaexp = 86400;
static int backinexp = 3000;
char *backsmtpserver = NULL;
static int backsmtpport = 25;
static int addrsubdomain = 0;
static unsigned int smtpwait = 0;
char hostname[MAXHOSTNAMELEN+1];
char *backlisttxt = NULL;

struct mlfiPriv {
	int	sockfd;
#ifdef BITBUCKET
	SLIST_HEAD(, entry)	brcpt;
#endif
} mlfi_priv;


static sfsistat mlfi_cleanup(SMFICTX *);

static sfsistat
upbacklist(char *rcptaddr, int resp)
{
	sfsistat rstat = SMFIS_CONTINUE;

	struct backent *backadd;
	struct timeval gnow;

#ifndef LINUX
	struct timezone tz;

	gettimeofday(&gnow, &tz);
#else
	gettimeofday(&gnow, NULL);
#endif

	backadd = (struct backent *)malloc(sizeof(struct backent));
	if ((backadd->rcptaddr = strdup(rcptaddr)) == NULL)
	{
		syslog (LOG_ERR, "scam-back cannot alloc");
		rstat = SMFIS_TEMPFAIL;
	} else {
		backadd->tv = gnow;
		backadd->resp = resp;
		WRLOCK(back_lock);
		TAILQ_INSERT_TAIL(&backhead, backadd, backentries);
		UNLOCK(back_lock);
	}

	return rstat;
}

static int
lookupbacklist(char *rcptaddr)
{

	struct backent *bent;
	struct backent *backnext;
	int backexpire = 0;
	int ret = -1;
	struct timeval gnow;

#ifndef LINUX
	struct timezone tz;

	gettimeofday(&gnow, &tz);
#else
	gettimeofday(&gnow, NULL);
#endif

	WRLOCK(back_lock);
	for (bent = TAILQ_FIRST(&backhead); bent; bent = backnext)
	{
		backnext = TAILQ_NEXT(bent, backentries);

		if (( bent->resp == 1) && (gnow.tv_sec - bent->tv.tv_sec > backinexp))
		{
			backexpire = 1;
		} else if (gnow.tv_sec - bent->tv.tv_sec > backvaexp)
		{
			backexpire = 1;
		}

		if (backexpire == 1)
		{
			TAILQ_REMOVE(&backhead, bent, backentries);
			free(bent->rcptaddr);
			free(bent);
			backexpire = 0;
		}
		else if (strcasecmp(bent->rcptaddr, rcptaddr) == 0)
		{
			ret = bent->resp;
			break;
		}
	}
	UNLOCK(back_lock);

	return ret;
}

int
loadbacklist()
{
	int ret = 0;
	FILE *fh;
	char line[512];
	int response;
	char email[500];

	if (backlisttxt == NULL)
		return ret;

	if ((fh = fopen( backlisttxt, "r")) == NULL) {
		return 1;
	}

	while( fgets(line, 511, fh) )
	{
		if (strlen(line) > 5)
		{
			if (sscanf( line, "%u %500[^\n]", &response, email) == 2)
			{
				upbacklist(email, response);
			}
		}
	}
	fclose(fh);

	return ret;
}

int
savebacklist()
{

	struct backent *bent;
	struct backent *backnext;
	int ret = 0;
	FILE *fh;
	char line[512];

	if (backlisttxt == NULL)
		return ret;

	if ((fh = fopen( backlisttxt, "w+")) == NULL) {
		return 1;
	}
	syslog (LOG_INFO, "saving cache %s", backlisttxt);
	WRLOCK(back_lock);
	for (bent = TAILQ_FIRST(&backhead); bent; bent = backnext)
	{
		backnext = TAILQ_NEXT(bent, backentries);

		snprintf( line, 511, "%u %s\n", bent->resp, bent->rcptaddr);
		if (fputs(line, fh) != 0)
		{
			UNLOCK(back_lock);
			fclose(fh);
			return 1;
		}
	}
	UNLOCK(back_lock);
	fclose(fh);

	return ret;
}

static int
backerr(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;

	close(priv->sockfd);
	priv->sockfd = -2;
	smfi_setreply( ctx, "450", "4.7.0", TEMPFAILTEXT);

	return 0;
}

static int
smtpopen(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;
	int rc;
	char *buffer;
	int lenbuf;

	if ((priv->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		syslog (LOG_WARNING, "cannot create socket");
		return 1;
	}
	rc = clientconn( priv->sockfd, backsmtpserver, backsmtpport, 1500);
	if ( 0 != rc)
	{
		backerr(ctx);
		syslog (LOG_WARNING, "cannot connect");
		return 0;
	}

	if ((buffer = malloc(RECVBUFLEN)) == NULL)
	{
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}
	rc = clientread( priv->sockfd, &buffer, RECVBUFLEN, 5 + smtpwait);

	if (rc < 5)
	{
		free(buffer);
		backerr(ctx);
		syslog (LOG_WARNING, "cannot read banner");
		if (smtpwait < MAXSMTPWAIT)
		{
			WRLOCK(back_lock);
			smtpwait++;
			UNLOCK(back_lock);
			syslog (LOG_INFO, "increased smtpwait to %d", smtpwait);
		}
		return 0;
	}

	if ((*buffer != '2') || (*(buffer+1) != '2') || (*(buffer+2) != '0'))
	{
		free(buffer);
		backerr(ctx);
		return 1;
	}

	free(buffer);
	if ((buffer = malloc(RECVBUFLEN)) == NULL)
	{
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}

#ifdef EHLO
	snprintf( buffer, RECVBUFLEN, "EHLO %s\r\n", hostname);
#else
	snprintf( buffer, RECVBUFLEN, "HELO %s\r\n", hostname);
#endif
	lenbuf = strlen(buffer);
	rc = clientwrite( priv->sockfd, buffer, lenbuf);

	if ( 0 != rc)
	{
		free(buffer);
		backerr(ctx);
		syslog (LOG_ERR, "cannot writehelo");
		return 1;
	}

	rc = clientread( priv->sockfd, &buffer, RECVBUFLEN, 2 + smtpwait );

	if (rc < 5)
	{
		free(buffer);
		backerr(ctx);
		syslog (LOG_ERR, "cannot heloreply");
		if (smtpwait < MAXSMTPWAIT)
		{
			WRLOCK(back_lock);
			smtpwait++;
			UNLOCK(back_lock);
			syslog (LOG_INFO, "increased smtpwait to %d", smtpwait);
		}
		return 1;
	}

	if ((*buffer != '2') || (*(buffer+1) != '5') || (*(buffer+2) != '0'))
	{
		buffer[rc]= '\0';
		syslog (LOG_ERR, "cannot helocode");
		free(buffer);
		backerr(ctx);
		return 1;
	}

	free(buffer);
	if ((buffer = malloc(RECVBUFLEN)) == NULL)
	{
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}

	snprintf( buffer, RECVBUFLEN, "MAIL FROM:<postmaster+backscatter@%s>\r\n", hostname);
	lenbuf = strlen(buffer);
	rc = clientwrite( priv->sockfd, buffer, lenbuf);

	if ( 0 != rc)
	{
		free(buffer);
		backerr(ctx);
		syslog (LOG_ERR, "cannot writemailfrom");
		return 1;
	}

	rc = clientread( priv->sockfd, &buffer, RECVBUFLEN , 3);

	if (rc < 5)
	{
		free(buffer);
		backerr(ctx);
		syslog (LOG_ERR, "cannot mailfromreply");
		return 1;
	}

	if ((*buffer != '2') || (*(buffer+1) != '5') || (*(buffer+2) != '0'))
	{
		if ((*buffer == '5') && (*(buffer+1) == '5'))
		{
			syslog (LOG_ERR, "backend did not accept sender address");
		} else {
			syslog (LOG_ERR, "cannot mailfromcode");
		}

		free(buffer);
		backerr(ctx);
		return 1;
	}
	free(buffer);

	return 0;
}

static int
smtpclose(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;
	int rc;
	char *buffer;
	int lenbuf;

	if ((buffer = malloc(RECVBUFLEN)) == NULL)
	{
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}

	snprintf( buffer, RECVBUFLEN, "RSET\r\n");
	lenbuf = strlen(buffer);
	rc = clientwrite( priv->sockfd, buffer, lenbuf);

	if ( 0 != rc)
	{
		free(buffer);
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}

	rc = clientread( priv->sockfd, &buffer, RECVBUFLEN, 3 );

	if (rc < 5)
	{
		free(buffer);
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}

	if ((*buffer != '2') || (*(buffer+1) != '5') || (*(buffer+2) != '0'))
	{
		free(buffer);
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}

	free(buffer);
	if ((buffer = malloc(RECVBUFLEN)) == NULL)
	{
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}

	snprintf( buffer, RECVBUFLEN, "QUIT\r\n");
	lenbuf = strlen(buffer);
	rc = clientwrite( priv->sockfd, buffer, lenbuf);

	if ( 0 != rc)
	{
		free(buffer);
		shutdown(priv->sockfd, 2);
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}

	rc = clientread( priv->sockfd, &buffer, RECVBUFLEN, 3 );

	if (rc < 5)
	{
		free(buffer);
		shutdown(priv->sockfd, 2);
		close(priv->sockfd);
		priv->sockfd = -2;
		return 1;
	}

	free(buffer);
	shutdown(priv->sockfd, 2);
	close(priv->sockfd);
	priv->sockfd = -2;

	return 0;
}

#ifndef ALLDOMAINS
int
check_dom(const char* domname)
{
	int ret = 0;
	struct doment *entre;
	char *domainp = NULL;
	int cmp;
	char *domnameLC = NULL;
	char *cp = NULL;
	char *entredomainLC = NULL;

	if ( strlen( domname ) < 1 )
		return ret;

	domnameLC = strdup( domname );
	if ( domnameLC == NULL )
		return ( ret );

	for ( cp = domnameLC; *cp; ++cp )
		*cp = tolower( *cp );

	SLIST_FOREACH( entre, &domlist, domentries )
	{
		if (entredomainLC != NULL)
			free(entredomainLC);

		entredomainLC = strdup( entre->domain );
		if ( entredomainLC == NULL )
		{
			free( domnameLC );
			return ret;
		}

		for ( cp = entredomainLC; *cp; ++cp )
			*cp = tolower( *cp );

		cmp = strcmp( domnameLC, entredomainLC );

		if ( cmp == 0 )
		{
			ret = 1;
			break;
		}

		if ((addrsubdomain == 1) && (cmp > 0))
		{
			domainp = strstr( domnameLC, entredomainLC );

			if ( domainp == NULL )
				continue;

			cmp = strcmp( domainp, entredomainLC );

			if (( cmp == 0) && (domainp != domnameLC) && (*(domainp - 1) == '.' ))
			{
				ret = 1;
				break;
			}
		}
	}

	free( domnameLC );
	if (entredomainLC != NULL)
		free( entredomainLC );

	return ret;
}
#endif /* ALLDOMAINS */

static sfsistat
mlfi_connect(SMFICTX *ctx, char *hostname,  _SOCK_ADDR *hostaddr)
{
	struct mlfiPriv *priv= MLFIPRIV;
	char *daemonname;
	struct sockaddr_in  *remoteaddr;

	priv = malloc(sizeof *priv);
	if (priv == NULL) {
		syslog (LOG_ERR, "cannot allocate priv");
		return SMFIS_TEMPFAIL;
	}
	memset(priv, '\0', sizeof *priv);

	/* set the private data */
	if (smfi_setpriv(ctx, priv) != MI_SUCCESS)
	{
		smfi_setpriv(ctx, priv);
		free(priv);

		syslog (LOG_ERR, "cannot setpriv");
		(void) mlfi_cleanup(ctx);
        return SMFIS_TEMPFAIL;
	}

	priv->sockfd = -2;

	remoteaddr = (struct sockaddr_in *) hostaddr;

	if ((remoteaddr != NULL) && (remoteaddr->sin_family == AF_INET))
	{
		if (remoteaddr->sin_addr.s_addr == inet_addr("127.0.0.1"))
			return SMFIS_ACCEPT;
	}

	daemonname = smfi_getsymval(ctx, "{daemon_name}");
	if (daemonname != NULL)
	{
		if (strcasecmp(daemonname, "MSA") == 0)
		{
				return SMFIS_ACCEPT;
		}
	}

	return SMFIS_CONTINUE;
}

#ifdef BITBUCKET
static sfsistat
mlfi_envfrom(SMFICTX *ctx, char **argv)
{
	struct mlfiPriv *priv = MLFIPRIV;

	SLIST_INIT(&priv->brcpt);
	return SMFIS_CONTINUE;
}
#endif

static sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **argv)
{
	char *rcptaddr;
	int rc;
	char *buffer;
	int lenbuf;
	char *domain;
#ifdef BITBUCKET
	struct entry *rcpt;
#endif

	struct mlfiPriv *priv = MLFIPRIV;

	rcptaddr  = smfi_getsymval(ctx, "{rcpt_addr}");

	if (rcptaddr == NULL)
	{
		syslog (LOG_ERR, "cannot get rcpt address");
		return SMFIS_TEMPFAIL;
	}

	domain = rfc822domain(rcptaddr);
#ifdef ALLDOMAINS
	if (domain != NULL)
#else
	if ((domain != NULL) && (check_dom( domain) == 1))
#endif
	{
		rc = lookupbacklist(rcptaddr);
		switch (rc)
		{
			case 0:
				return SMFIS_CONTINUE;
				break;

			case 1:
#ifdef BITBUCKET
				rcpt = (struct entry *)malloc(sizeof(struct entry));
				if ((rcpt->c = strdup(rcptaddr)) == NULL)
				{
					syslog (LOG_ERR, "cannot alloc rcpt");
					(void) mlfi_cleanup(ctx);
					return SMFIS_TEMPFAIL;
				}
				SLIST_INSERT_HEAD(&priv->brcpt, rcpt, entries);
				return SMFIS_CONTINUE;
#else
				if ((buffer = malloc(1024)) == NULL)
				{
					return SMFIS_TEMPFAIL;
				}
				snprintf( buffer, 1024, "%s", RCPTREJTEXT);
				smfi_setreply( ctx, "550", "5.1.1", buffer);
				free(buffer);
				return SMFIS_REJECT;
#endif /* BITBUCKET */
				break;
		}

		if (priv->sockfd == -2)
		{
			if (smtpopen(ctx) != 0)
				return SMFIS_CONTINUE;
		}

		if (priv->sockfd >= 0)
		{
			if ((buffer = malloc(RECVBUFLEN)) == NULL)
			{
				return SMFIS_TEMPFAIL;
			}
			snprintf( buffer, RECVBUFLEN, "RCPT TO:<%s>\r\n",rcptaddr);
			lenbuf = strlen(buffer);
			rc = clientwrite( priv->sockfd, buffer, lenbuf);

			if ( 0 != rc)
			{
				free(buffer);
				backerr(ctx);
				syslog (LOG_ERR, "cannot rcpttosend");
				return SMFIS_TEMPFAIL;
			}

			rc = clientread( priv->sockfd, &buffer, RECVBUFLEN , 3);

			if (rc < 5)
			{
				free(buffer);
				backerr(ctx);
				syslog (LOG_ERR, "cannot rcpttoreply on  %d", priv->sockfd);
				return SMFIS_TEMPFAIL;
			} else {
				if (((*buffer == '5') && (*(buffer+1) == '5') && (*(buffer+2) == '0')) || ((*buffer == '5') && (*(buffer+1) == '5') && (*(buffer+2) == '3')))
				{
					upbacklist(rcptaddr, 1);
#ifdef BITBUCKET
					rcpt = (struct entry *)malloc(sizeof(struct entry));
					if ((rcpt->c = strdup(rcptaddr)) == NULL)
					{
						free(buffer);
						syslog (LOG_ERR, "cannot alloc rcpt");
						(void) mlfi_cleanup(ctx);
						return SMFIS_TEMPFAIL;
					}
					SLIST_INSERT_HEAD(&priv->brcpt, rcpt, entries);
#else
					snprintf( buffer, 1023, "%s", RCPTREJTEXT);
					smfi_setreply( ctx, "550", "5.1.1", buffer);
					free(buffer);
					return SMFIS_REJECT;
#endif /* BITBUCKET */
				}
				else if ((*buffer == '2') && (*(buffer+1) == '5') && (*(buffer+2) == '0'))
				{
					upbacklist(rcptaddr, 0);
				}
			}
			free(buffer);
		}
	}
	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	struct mlfiPriv *priv = MLFIPRIV;

	if (priv->sockfd >= 0)
	{
		smtpclose(ctx);
	}

	return SMFIS_CONTINUE;
}

#ifdef BITBUCKET
static sfsistat
mlfi_eom(SMFICTX *ctx)
{
	struct mlfiPriv *priv= MLFIPRIV;
	struct entry *rcpt;

	while (!SLIST_EMPTY(&priv->brcpt))
	{
		rcpt = SLIST_FIRST(&priv->brcpt);
		if (smfi_delrcpt( ctx, rcpt->c) == MI_FAILURE)
		{
			syslog (LOG_ERR, "cannot delete recipient");
		}
		free(rcpt->c);
		SLIST_REMOVE_HEAD(&priv->brcpt, entries);
		free(rcpt);
	}
	return SMFIS_ACCEPT;
}
#endif

sfsistat
mlfi_abort(SMFICTX *ctx)
{

	mlfi_cleanup(ctx);

	return SMFIS_CONTINUE;
}

static sfsistat
mlfi_cleanup(SMFICTX *ctx)
{
#ifdef BITBUCKET
	struct entry *rcpt;
#endif
	struct mlfiPriv *priv = MLFIPRIV;

	if (priv == NULL)
		return 0;

	if (priv->sockfd >= 0)
	{
		smtpclose(ctx);
	}

#ifdef BITBUCKET
	while (!SLIST_EMPTY(&priv->brcpt))
	{
		rcpt = SLIST_FIRST(&priv->brcpt);
		free(rcpt->c);
		SLIST_REMOVE_HEAD(&priv->brcpt, entries);
		free(rcpt);
	}
#endif

	return 0;

}

static sfsistat
mlfi_close(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;

	mlfi_cleanup(ctx);

	if (priv)
	{
		free(priv);
	}
	smfi_setpriv(ctx, NULL);

	return SMFIS_CONTINUE;
}

struct smfiDesc smfilter =
{
	"scam-back",	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
#ifdef BITBUCKET
	SMFIF_ADDHDRS|SMFIF_DELRCPT,
#else
	SMFIF_ADDHDRS,	/* flags */
#endif
	mlfi_connect,		/* connection info filter */
	NULL,		/* SMTP HELO command filter */
#ifdef BITBUCKET
	mlfi_envfrom,
#else
	NULL,		/* envelope sender filter */
#endif
	mlfi_envrcpt,	/* envelope recipient filter */
	mlfi_header,				/* header filter */
	NULL,	/* end of header */
	NULL,			/* body block filter */
#ifdef BITBUCKET
	mlfi_eom,
#else
	NULL,	/* end of message */
#endif
	mlfi_abort,	/* message aborted */
	mlfi_close,	/* connection cleanup */
};

static void
usage()
{
	fprintf(stdout, "scam-back version %s\n", VERSION);
    fprintf(stdout, "usage: scam-back -p protocol:address [-u user] [-g group] [-T timeout] [-f config] [-P pidfile] [-b path] [-R] [-D]\n");
	fprintf(stdout, "          -D run as a daemon\n");
	fprintf(stdout, "          -u run as specified user\n");
	fprintf(stdout, "          -f use specified configuration file\n");
	fprintf(stdout, "          -P use specified pid file\n");
	fprintf(stdout, "          -b read and save recipient addresses to file\n");
}

static void
catch_signal( int signo )
{
	switch (signo)
	{
		case SIGUSR1:
		   syslog (LOG_NOTICE, "Caught SIGUSR1, exiting...");
			smfi_stop();
			sleep(10);
			exit (0) ;
			break;

		case SIGTERM:
			sleep(10);
			exit (0) ;
			break;
	}

}

int
write_pid(char *pidfile)
{
	char buf[20];
	int fd;
	long pid;

	pid = getpid ();

	if ((fd = open (pidfile, O_CREAT | O_TRUNC | O_WRONLY, 0600)) == -1)
	{
		syslog (LOG_ERR, "cannot open pidfile");
	} else {
		snprintf (buf, sizeof (buf), "%ld", (long) pid);
		if (write (fd, buf, strlen (buf)) != strlen (buf)) {
			syslog (LOG_ERR, "cannot write to pidfile");
		}
		close(fd);
	}
	return pid;
}

void
daemonize(char *pidfile)
{

	signal (SIGUSR1, catch_signal);
	signal (SIGTERM, catch_signal);

	(void)close(0);
	(void)open("/dev/null", O_RDONLY, 0);
	(void)close(1);
	(void)open("/dev/null", O_RDONLY, 0);
	(void)close(2);
	(void)open("/dev/null", O_RDONLY, 0);

	switch (fork ())
	{
		case 0:
			syslog (LOG_INFO, "scam-back %s running", VERSION);
			break;

		case -1:
			perror ("cannot fork\n");
			exit (3);
			break;

		default:
			exit(0);
	}

	if (setsid() < 0)
		exit(1);

	write_pid(pidfile);
	chdir("/");

}

#ifdef USEMAILERTABLE
int
read_mailertable()
{
	FILE *fh;
	struct doment *domadd;
	char line[LINELENGTH + 1];
	char buf[LINELENGTH + 1];
	int first = 0;
	char *token;

	if ((fh = fopen( MAILERTABLE, "r")) == NULL) {
		return 1;
	}

	syslog (LOG_INFO, "reading mailertable");

	while( fgets(line, LINELENGTH, fh) )
	{
		if (line[0] == '#')
			continue;

		if ((strlen(line) > 3) && (sscanf( line, "%256[A-Za-z0-9-.]", buf) == 1))
		{
			domadd = (struct doment *)malloc(sizeof(struct doment));
			if ((domadd->domain = strdup(buf)) == NULL)
			{
				fclose(fh);
				return 1;
			}
			SLIST_INSERT_HEAD(&domlist, domadd, domentries);
			syslog (LOG_DEBUG, "BackAddrDomain %s", buf);
			if (first == 0)
			{
				first = 1;
				token = strtok(line, "[");
				if (token != NULL)
				{
					token = strtok(NULL, "[");
					if (token != NULL)
					{
						if (sscanf( token, "%256[0-9.]", buf) == 1)
						{
							backsmtpserver = strdup(buf);
							syslog (LOG_DEBUG, "BackSMTPServer %s", buf);
						}
					}
				}
			}
		}
	}
	fclose(fh);

	return 0;
}
#endif /* USEMAILERTABLE */

int back_readconf(const char* conf)
{
	FILE *fh;
	char line[LINELENGTH + 1];
	char buf[LINELENGTH + 1];

	int lline;
	int lineno = 0;
#ifndef USEMAILERTABLE
	struct doment *domadd;
#endif

#ifdef BITBUCKET
	syslog (LOG_INFO, "bitbucket enabled");
#endif
	if ((fh = fopen( conf, "r")) == NULL)
	{
		return 1;
	}

	while( fgets(line, LINELENGTH, fh) )
	{
		lineno++;
		if (line[0] == '#')
			continue;

		lline = strlen(line);
		if (lline > 16)
		{
			if (sscanf( line, "BackValidAddrExp:%7[0-9]", buf) == 1)
			{
				int num;

				num = atoi(buf);
				if (num > 0)
					backvaexp = num;

				syslog (LOG_DEBUG, "BackValidAddrExp set to %d seconds", backvaexp);
			} else if (sscanf( line, "BackInvalidAddrExp:%7[0-9]", buf) == 1)
			{
				int num;

				num = atoi(buf);
				if (num > 0)
					backinexp = num;

				syslog (LOG_DEBUG, "BackInvalidAddrExp set to %d seconds", backinexp);
			}
#ifndef USEMAILERTABLE
			else if (sscanf( line, "BackSMTPServer:%16[0-9-.]", buf) == 1)
			{
				if (strlen(buf) > 6)
				{
					backsmtpserver = strdup(buf);
					syslog (LOG_DEBUG, "BackSMTPServer %s", buf);
				}
			}
			else if (sscanf( line, "BackAddrDomain:%256[A-Za-z0-9-.]", buf) == 1)
			{
				if (strlen(buf) > 3)
				{
					domadd = (struct doment *)malloc(sizeof(struct doment));
					if ((domadd->domain = strdup(buf)) == NULL)
					{
						return 1;
					}
					SLIST_INSERT_HEAD(&domlist, domadd, domentries);
					syslog (LOG_DEBUG, "BackAddrDomain %s", buf);
				}
			}
#endif
			else if (sscanf( line, "BackSMTPPort:%5[0-9]", buf) == 1)
			{
				int num;

				num = atoi(buf);
				if (num > 0)
					backsmtpport = num;

				syslog (LOG_DEBUG, "BackSMTPPort set to %d", backsmtpport);
			}
			else if (sscanf( line, "BackAddrSubdomains=%3[a-zA-Z]", buf) == 1)
			{
				if (strcasecmp("yes", buf) == 0)
				{
					addrsubdomain = 1;
					syslog (LOG_DEBUG, "BackAddrSubdomains %s", buf);
				}
			}
			else if (sscanf( line, "BackList:%255[^\n]", buf) == 1)
			{
				if (strlen(buf) > 3)
				{
					backlisttxt = strdup(buf);
					syslog (LOG_DEBUG, "BackList %s", buf);
				}
			}
		}
	}
	fclose(fh);

#ifdef ALLDOMAINS
	syslog (LOG_DEBUG, "BackAddrDomain all domains");
#endif
	return 0;
}

int
main(int argc, char *argv[])
{
	int c;
	int ret;
	const char *args = "p:T:h:u:f:g:b:P:D";
	extern char *optarg;
	int daemonmode = 0;
	struct passwd *passwd = NULL;
	struct group *grp;
	char *user = NULL;
	char *group = NULL;
	uid_t uid = 0;
	gid_t gid = 0;
	char *conf = NULL;
	char *pidfile =NULL;

	/* already a daemon */
	if(getppid()==1)
		return 0;

	/* Process command line options */
	while ((c = getopt(argc, argv, args)) != (char)EOF)
	{
		switch (c)
		{
		  case 'p':
			if (optarg == NULL || *optarg == '\0')
			{
				(void) fprintf(stderr, "Illegal connection: %s\n", optarg);
				exit(EX_USAGE);
			}
			if (smfi_setconn(optarg) == MI_FAILURE)
			{
				(void) fprintf(stderr, "smfi_setconn failed");
				exit(EX_SOFTWARE);
			}

			/*
				** If we're using a local socket, make sure it doesn't
				** already exist.
			*/
            if(strncmp(optarg, "unix:", 5) == 0)
                unlink(optarg + 5);
            else if(strncmp(optarg, "local:", 6) == 0)
                unlink(optarg + 6);

			break;

		  case 'T':
            if (optarg == NULL || *optarg == '\0')
            {
                (void) fprintf(stderr, "Illegal timeout: %s\n", optarg);
                exit(EX_USAGE);
            }
            if(smfi_settimeout(atoi(optarg)) == MI_FAILURE)
            {
                (void) fputs("smfi_settimeout failed", stderr);
                exit(EX_SOFTWARE);
            }
            break;

			case 'u':
				if (optarg == NULL || *optarg == '\0')
				{
					(void) fprintf(stderr, "Invalid username\n");
					exit(EX_USAGE);
				}
				user = strdup(optarg);
				if ((passwd = getpwnam(user)) != NULL)
				{
					uid = passwd->pw_uid;
					gid = passwd->pw_gid;
				}
				(void) endpwent();
				break;

			case 'g':
				if (optarg == NULL || *optarg == '\0')
				{
					(void) fprintf(stderr, "Invalid group name\n");
					exit(EX_USAGE);
				}
				group = strdup(optarg);
				if ((grp = getgrnam(group)) != NULL)
				{
					gid = grp->gr_gid;
				}
				(void) endgrent();
				break;

			case 'f':
				if (optarg == NULL || *optarg == '\0')
				{
					(void) fprintf(stderr, "Invalid configuration file\n");
					exit(EX_USAGE);
				}
				conf = strdup(optarg);
				break;

			case 'P':
				if (optarg == NULL || *optarg == '\0')
				{
					(void) fprintf(stderr, "Invalid pid file\n");
					exit(EX_USAGE);
				}
				pidfile = strdup(optarg);
				break;

			case 'b':
				if (optarg == NULL || *optarg == '\0')
				{
					(void) fprintf(stderr, "Invalid file for backup of recipient addresses\n");
					exit(EX_USAGE);
				}
				backlisttxt = strdup(optarg);
				break;

		  case 'd':
			if (optarg == NULL || *optarg == '\0')
            {
                (void) fprintf(stderr, "Illegal debug value: %s\n", optarg);
                exit(EX_USAGE);
            }
			if (smfi_setdbg(atoi(optarg)) == MI_FAILURE)
				fprintf(stderr, "smfi_setdbg enabled\n");
			break;

		  case 'D':
			  daemonmode = 1;
			  break;

		  case 'h':
		  default:
			usage();
			exit(0);

		}
	}

	(void) closelog();
	openlog("scam-back", LOG_PID | LOG_NDELAY, LOG_MAIL);

	setgid(gid);
	setuid(uid);

	if (!getuid() || !geteuid())
	{
		syslog (LOG_ERR, "scam-back cannot run as root");
		exit(0);
	}

	if (smfi_register(smfilter) == MI_FAILURE)
	{
		fprintf(stderr, "smfi_register failed\n");
		syslog (LOG_ERR, "smfi_register failed");
		exit(EX_UNAVAILABLE);
	}
#ifdef SM813
	if (smfi_opensocket(0) == MI_FAILURE)
	{
		syslog (LOG_ERR, "smfi_opensocket failed");
		exit(EX_UNAVAILABLE);
	}
#endif
	memset(hostname, '\0', sizeof hostname);
	if (gethostname(hostname, sizeof hostname) != 0)
	{
		fprintf(stderr, "gethostname failed\n");
		syslog (LOG_ERR, "gethostname failed");
		exit(EX_UNAVAILABLE);
	}

	SLIST_INIT( &domlist);

	if (conf == NULL)
		conf = strdup(SCAMCONF);

	back_readconf(conf);
	free(conf);

#ifdef USEMAILERTABLE
	read_mailertable();
#endif

	if (backsmtpserver == NULL)
	{
		syslog (LOG_ERR, "BackSMTPServer not defined");
		exit(EX_OSERR);
	}

	if (SLIST_EMPTY(&domlist))
	{
		syslog (LOG_ERR, "BackAddrDomain not defined");
		exit(EX_OSERR);
	}

	TAILQ_INIT(&backhead);

	if ((ret = pthread_rwlock_init(&back_lock, NULL)) != 0)
	{
		syslog(LOG_ERR,  "pthread_rwlock_init failed: %s", strerror(ret));
		exit(EX_OSERR);
	}
	loadbacklist();

	if (pidfile == NULL)
		pidfile = strdup(PIDFILE);

	if (daemonmode == 1)
	{
		daemonize(pidfile);
	}

	if (group == NULL)
		umask(0177);
	else
		umask(0117);

	ret = smfi_main();
	savebacklist();
	unlink(pidfile);
	syslog (LOG_INFO, "Exit");
	return(ret);
}
