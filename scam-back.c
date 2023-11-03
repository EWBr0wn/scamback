/*
Copyright © 2006-2009 Eland Systems All Rights Reserved.

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
#include <netdb.h>
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
#define MAILFROMUSER "postmaster+backscatter"

#define VERSION "1.5.0"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#ifdef USEMAILERTABLE
#define DEFMAILERTABLE "/etc/mail/mailertable"
#endif

#define MAXSMTPWAIT 5
#define RECVBUFLEN	1024
#define DEFSMTPPORT 25

struct backent {
	int resp;
	struct timeval tv;
	char	*rcptaddr;
	TAILQ_ENTRY(backent)	backentries;
};

pthread_rwlock_t back_lock;

TAILQ_HEAD(backlist, backent);
struct backlist backhead;

struct doment {

#ifndef ALLDOMAINS
	short int backsmtpport;
	struct sockaddr_storage backss;
#ifdef FALLBACKEND
	short int backsmtpport2;
	unsigned int backrefused2;
	unsigned int backsmtpbackoff2;
	struct sockaddr_storage backss2;
#endif
#endif /* ALLDOMAINS */
	char	*domain;
	SLIST_ENTRY(doment)	domentries;
};

SLIST_HEAD(, doment) domlist;

struct CIDR {
	short int masklen;
	unsigned int ip;
	SLIST_ENTRY(CIDR)	cidrs;
};

SLIST_HEAD(, CIDR)	backcidr;

struct entry {
	char	*c;
	SLIST_ENTRY(entry)	entries;
};

SLIST_HEAD(, entry) daemonlist;

struct domconn {
	short int backsmtpport;
	unsigned int backrefused;
	unsigned int backsmtpbackoff;
	struct sockaddr_storage  ss;

#ifdef FALLBACKEND
	short int backsmtpport2;
	unsigned int backrefused2;
	unsigned int backsmtpbackoff2;
	struct sockaddr_storage  ss2;
#endif
};

pthread_rwlock_t skipvrfy_lock;

static int backvaexp = 86400;
static int backinexp = 3000;
#ifdef ALLDOMAINS
struct sockaddr_storage backss;
#endif
static int backsmtpport = DEFSMTPPORT;
static int addrsubdomain = 0;
static int backerrfail = 0;
static unsigned int smtpwait = 0;
static unsigned int timeoutconnect = 1500;
static unsigned int timeoutreply = 3;
static unsigned int backsmtpbackoff = 60;
unsigned int backrefused = 0;
char hostname[MAXHOSTNAMELEN+1];
char *backlisttxt = NULL;
#ifdef USEMAILERTABLE
char *mailertable = NULL;
#endif

struct mlfiPriv {
	short int backsmtpport;
	int	sockfd;
	struct sockaddr_storage backss;
#ifdef FALLBACKEND
	short int backsmtpport2;
	struct sockaddr_storage backss2;
#endif

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
		if (fputs(line, fh) == EOF)
		{
			UNLOCK(back_lock);
			fclose(fh);
			syslog (LOG_ERR, "writing cache error %s", strerror(errno));
			return 1;
		}
	}
	UNLOCK(back_lock);
	fclose(fh);

	return ret;
}

static int
sockclose(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;

	if (priv->sockfd >= 0)
		if (close(priv->sockfd) != 0)
			syslog (LOG_ERR, "socket close error %s", strerror(errno));

	priv->sockfd = -2;

	return 0;
}

static int
backerr(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;

	if (priv->sockfd >= 0)
		if (close(priv->sockfd) != 0)
			syslog (LOG_ERR, "close fd error %s", strerror(errno));

	priv->sockfd = -2;
	smfi_setreply( ctx, "451", "4.7.0", TEMPFAILTEXT);

	return 0;
}

static int
smtpcmd(int sockfd, const char *cmd, const char *param, const char *smtpcode)
{

	int lenbuf;
	int rc;
	char *buffer;

	if ((buffer = malloc(RECVBUFLEN)) == NULL)
		return 1;

	if ((strlen(cmd) == 4) && (strlen(param) != 0))
	{
		snprintf( buffer, RECVBUFLEN, "%s %s\r\n", cmd, param);
	} else {
		snprintf( buffer, RECVBUFLEN, "%s%s\r\n", cmd, param);
	}

	lenbuf = strlen(buffer);
	rc = clientwrite( sockfd, buffer, lenbuf);
	if ( 0 > rc)
	{
		free(buffer);

		syslog (LOG_ERR, "cannot send %s", cmd);
		return 1;
	}

	rc = clientread( sockfd, &buffer, RECVBUFLEN , 2000);
	if (rc < 5)
	{
		free(buffer);

		syslog (LOG_ERR, "cannot read %s reply", cmd);
		return 2;
	}

#ifdef VERBOSE
	buffer[rc] = '\0';
	syslog (LOG_DEBUG, "%s response %s", cmd, buffer);
#endif

	if ((*buffer != smtpcode[0]) || (*(buffer+1) != smtpcode[1]) || (*(buffer+2) != smtpcode[2]))
	{
		if ((*buffer == '5') && (*(buffer+1) == '5'))
		{
			syslog (LOG_ERR, "backend did not accept %s", cmd);
		} else {
			syslog (LOG_ERR, "unexpected SMTP reply code on %s", cmd);
		}

		free(buffer);
		return 1;
	}

	free(buffer);
	return 0;
}

static int
smtpopen(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;
	int rc;
	char *buffer;

#ifdef ALLDOMAINS
	rc = clientconn( &(priv->sockfd), backss, backsmtpport, timeoutconnect);
#else
	rc = clientconn( &(priv->sockfd), priv->backss, priv->backsmtpport, timeoutconnect);
#endif /* ALLDOMAINS */

	/* socket or addr error */
	if (rc == -3)
		return 1;

	if ( 0 != rc)
	{
		sockclose(ctx);
		if ((buffer = malloc(MAXHOSTNAMELEN)) == NULL)
			return 1;

#ifdef ALLDOMAINS
		if (getnameinfo((struct sockaddr *) &backss, backss.ss_len,  buffer, MAXHOSTNAMELEN, NULL, 0, NI_NUMERICHOST) == 0)
			syslog (LOG_WARNING, "cannot connect to backend SMTP at %s status %s", buffer, strerror(errno));

		free(buffer);
#else
		if (getnameinfo((struct sockaddr *) &priv->backss, priv->backss.ss_len,  buffer, MAXHOSTNAMELEN, NULL, 0, NI_NUMERICHOST) == 0)
			syslog (LOG_WARNING, "cannot connect to backend SMTP at %s status %s", buffer, strerror(errno));

		free(buffer);
#ifdef FALLBACKEND
	if (priv->backsmtpport > 0)
	{
		rc = clientconn( &(priv->sockfd), priv->backss2, priv->backsmtpport2, timeoutconnect);

		if (rc == -3)
			return 1;

		if ( 0 != rc)
		{
			sockclose(ctx);
			if ((buffer = malloc(MAXHOSTNAMELEN)) == NULL)
				return 1;

			if (getnameinfo((struct sockaddr *) &priv->backss2, priv->backss2.ss_len,  buffer, MAXHOSTNAMELEN, NULL, 0, NI_NUMERICHOST) == 0)
				syslog (LOG_WARNING, "cannot connect to backend SMTP at %s status %s", buffer, strerror(errno));

			free(buffer);
		}
		return 1;
	}

#endif /* FALLBACKEND */
#endif /* ALLDOMAINS */
#ifndef FALLBACKEND
		return 2;
#endif
	}
#ifdef VERBOSE
#ifdef ALLDOMAINS
		syslog (LOG_DEBUG, "Connected to backend SMTP\n");
#else
		if ((buffer = malloc(MAXHOSTNAMELEN)) == NULL)
			return 1;

		/* port can be incorrect */
		if (getnameinfo((struct sockaddr *) &priv->backss, priv->backss.ss_len,  buffer, MAXHOSTNAMELEN, NULL, 0, NI_NUMERICHOST) == 0)
			syslog (LOG_DEBUG, "Connected to backend SMTP at %s:%d\n", buffer, priv->backsmtpport);

		free(buffer);

#endif
#endif /* VERBOSE */

	if ((buffer = malloc(RECVBUFLEN)) == NULL)
	{
		sockclose(ctx);
		return 1;
	}
	rc = clientread( priv->sockfd, &buffer, RECVBUFLEN, timeoutreply + smtpwait);

	if (rc < 5)
	{
		free(buffer);
		sockclose(ctx);
		syslog (LOG_WARNING, "cannot read backend SMTP banner");
		if (smtpwait < MAXSMTPWAIT)
		{
			WRLOCK(back_lock);
			smtpwait++;
			UNLOCK(back_lock);
			syslog (LOG_INFO, "increased smtpwait to %d", smtpwait);
		}
		return 1;
	}

#ifdef VERBOSE
	buffer[rc]= '\0';
	syslog (LOG_DEBUG, "SMTP banner %s", buffer);
#endif

	if ((*buffer != '2') || (*(buffer+1) != '2') || (*(buffer+2) != '0'))
	{
		if (*buffer == '5')
			syslog (LOG_ERR, "backend SMTP service unavailable");
		free(buffer);
		backerr(ctx);
		return 1;
	}

	free(buffer);

#ifdef EHLO
	rc = smtpcmd( priv->sockfd, "EHLO", hostname, "250");
#else
	rc = smtpcmd( priv->sockfd, "HELO", hostname, "250");
#endif

	if ((rc == 2) && (smtpwait < MAXSMTPWAIT))
	{
		WRLOCK(back_lock);
		smtpwait++;
		UNLOCK(back_lock);
		syslog (LOG_INFO, "increased smtpwait to %d", smtpwait);
	}

	if ( 0 > rc)
		return 1;

	if ((buffer = malloc(RECVBUFLEN)) == NULL)
	{
		sockclose(ctx);
		return 1;
	}

	snprintf( buffer, RECVBUFLEN, ":<%s@%s>\r\n", MAILFROMUSER, hostname);
	rc = smtpcmd( priv->sockfd, "MAIL FROM", buffer, "250");
	free(buffer);

	if (0 > rc)
		return 1;

	return 0;
}

static int
smtpclose(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;
	int rc;

	rc = smtpcmd( priv->sockfd, "RSET", "", "250");

	if ( 0 > rc)
	{
		sockclose(ctx);
		return 1;
	}

	rc = smtpcmd( priv->sockfd, "QUIT", "", "221");

	if ( 0 > rc)
	{
		rc = 1;
	} else
		rc = 0;

	shutdown(priv->sockfd, 2);
	sockclose(ctx);

	return rc;
}

int
ip_cidr(const unsigned int ip, const short int masklen, const unsigned int checkip)
{
	unsigned int ipaddr = 0;
	unsigned int cidrip = 0;
	unsigned int subnet = 0;

	subnet = ~0;
	subnet = subnet << (32 - masklen);

	cidrip = htonl(ip) & subnet;
	ipaddr = ntohl(checkip) & subnet;

	if (cidrip == ipaddr)
		return 1;

	return 0;
}

int
check_ipv4(const unsigned int checkip)
{
	int ret = 0;
	struct CIDR *entcidr;

	RDLOCK(skipvrfy_lock);
	SLIST_FOREACH(entcidr, &backcidr, cidrs)
	{
		if (ip_cidr(entcidr->ip, entcidr->masklen, checkip) == 1)
		{
			ret = 1;
			break;
		}
	}
	UNLOCK(skipvrfy_lock);

	return ret;
}

#ifndef ALLDOMAINS
struct domconn
check_dom(const char* domname)
{
	struct domconn conninfo;
	struct doment *entre;
	char *domainp = NULL;
	int cmp;
	char *domnameLC = NULL;
	char *cp = NULL;
	char *entredomainLC = NULL;

	memset( &conninfo, '\0', sizeof(struct domconn));
	conninfo.backsmtpport = DEFSMTPPORT;

	if ( strlen( domname ) < 1 )
		return conninfo;

	domnameLC = strdup( domname );
	if ( domnameLC == NULL )
		return conninfo;

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
			return conninfo;
		}

		for ( cp = entredomainLC; *cp; ++cp )
			*cp = tolower( *cp );

		cmp = strcmp( domnameLC, entredomainLC );

		if ( cmp == 0 )
		{
			memcpy(&conninfo.ss, &(entre->backss), sizeof(conninfo.ss));
#ifdef FALLBACKEND
			memcpy(&conninfo.ss2, &(entre->backss2), sizeof(conninfo.ss2));
			conninfo.backsmtpport2 = entre->backsmtpport2;
#endif
			conninfo.backsmtpport = entre->backsmtpport;
			break;
		}

		if ((addrsubdomain == 1) && (cmp != 0))
		{
			domainp = strstr( domnameLC, entredomainLC );

			if ( domainp == NULL )
				continue;

			cmp = strcmp( domainp, entredomainLC );

			if (( cmp == 0) && (domainp != domnameLC) && (*(domainp - 1) == '.' ))
			{
				memcpy(&conninfo.ss, &(entre->backss), sizeof(conninfo.ss));
#ifdef FALLBACKEND
				memcpy(&conninfo.ss2, &(entre->backss2), sizeof(conninfo.ss2));
				conninfo.backsmtpport2 = entre->backsmtpport2;
#endif
				conninfo.backsmtpport = entre->backsmtpport;
				break;
			}
		}
	}

	free( domnameLC );
	if (entredomainLC != NULL)
		free( entredomainLC );

	return conninfo;
}
#endif /* ALLDOMAINS */

static sfsistat
mlfi_connect(SMFICTX *ctx, char *hostname,  _SOCK_ADDR *hostaddr)
{
	struct mlfiPriv *priv= MLFIPRIV;
	char *daemonname;
	struct sockaddr_in *remoteaddr;
	struct sockaddr_in6 *remoteaddr6;

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

	switch (hostaddr->sa_family)
	{
		case AF_INET:
			remoteaddr = (struct sockaddr_in *) hostaddr;

			if (remoteaddr != NULL)
			{
				if (check_ipv4(remoteaddr->sin_addr.s_addr) == 1)
					return SMFIS_ACCEPT;
			}
			break;

		case AF_INET6:
			remoteaddr6 = (struct sockaddr_in6 *) hostaddr;
			if (IN6_IS_ADDR_LOOPBACK(&remoteaddr6->sin6_addr))
				return SMFIS_ACCEPT;

			break;

		default:
			return SMFIS_ACCEPT;
	}

	daemonname = smfi_getsymval(ctx, "{daemon_name}");
	if (daemonname != NULL)
	{
		struct entry *daentry;
		SLIST_FOREACH(daentry, &daemonlist, entries)
		{
			if (strcasecmp(daemonname, daentry->c) == 0)
					return SMFIS_ACCEPT;
		}
	}

	return SMFIS_CONTINUE;
}


static sfsistat
mlfi_envfrom(SMFICTX *ctx, char **argv)
{
	struct mlfiPriv *priv = MLFIPRIV;
#ifdef BITBUCKET
	SLIST_INIT(&priv->brcpt);
#endif
#ifndef ALLDOMAINS
	priv->backsmtpport = 0;
#ifdef FALLBACKEND
	priv->backsmtpport2 = 0;
#endif
#endif
	return SMFIS_CONTINUE;
}


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
	if (domain != NULL)
	{
		struct domconn conninfo;
		conninfo = check_dom( domain);
		memcpy(&(priv->backss), &conninfo.ss,  sizeof(struct sockaddr_storage));
#ifdef FALLBACKEND
		memcpy(&(priv->backss2), &conninfo.ss2,  sizeof(struct sockaddr_storage));
		priv->backsmtpport2 = conninfo.backsmtpport2;
#endif
		priv->backsmtpport = conninfo.backsmtpport;
	} else
		return SMFIS_CONTINUE;

	if (priv->backss.ss_len > 0)
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
			/* Backoff state */
			int ret = 2;
#ifndef BACKOFF
			ret = smtpopen(ctx);
#else
			struct timeval bonow;
#ifndef LINUX
			struct timezone tz;

			gettimeofday(&bonow, &tz);
#else
			gettimeofday(&bonow, NULL);
#endif
			if (bonow.tv_sec - backrefused > backsmtpbackoff)
			{
				ret = smtpopen(ctx);
				if (ret == 2)
				{
					WRLOCK(back_lock);
					backrefused = bonow.tv_sec;
					UNLOCK(back_lock);
					syslog (LOG_INFO, "Backoff to backend SMTP for %d seconds", backsmtpbackoff);
				}
			}
#endif /* BACKOFF */

			if ( ret != 0)
			{
				if (backerrfail == 0)
				{
					return SMFIS_CONTINUE;
				} else {
					smfi_setreply( ctx, "451", "4.7.0", TEMPFAILTEXT);
					return SMFIS_TEMPFAIL;
				}
			}
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

			if ( 0 > rc)
			{
				free(buffer);
				backerr(ctx);
				syslog (LOG_ERR, "cannot send rcptto");
				return SMFIS_TEMPFAIL;
			}

			rc = clientread( priv->sockfd, &buffer, RECVBUFLEN , timeoutreply);

			if (rc < 5)
			{
				free(buffer);
				syslog (LOG_ERR, "cannot read rcptto reply on  %d", priv->sockfd);
				backerr(ctx);
				return SMFIS_TEMPFAIL;
			} else {
#ifdef VERBOSE
				buffer[rc]= '\0';
				syslog (LOG_DEBUG, "RCPT TO response %s", buffer);
#endif
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

#ifndef ALLDOMAINS
	priv->backsmtpport = 0;
#ifdef FALLBACKEND
	priv->backsmtpport2 = 0;
#endif
#endif /* ALLDOMAINS */
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
	mlfi_envfrom,
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
	fprintf(stdout, "  Features:\n");
#ifdef VERBOSE
	fprintf(stdout, "           VERBOSE\n");
#endif
#ifdef SM813
	fprintf(stdout, "           SM813\n");
#endif
#ifdef EHLO
	fprintf(stdout, "           EHLO\n");
#endif
#ifdef USEMAILERTABLE
	fprintf(stdout, "           USEMAILERTABLE\n");
#endif
#ifdef BITBUCKET
	fprintf(stdout, "           BITBUCKET\n");
#endif
#ifdef ALLDOMAINS
	fprintf(stdout, "           ALLDOMAINS\n");
#endif
#ifdef FALLBACKEND
	fprintf(stdout, "           FALLBACKEND\n");
#endif
#ifdef BACKOFF
	fprintf(stdout, "           BACKOFF\n");
#endif
    fprintf(stdout, "  usage: scam-back -p protocol:address [-u user] [-g group] [-T timeout]\n");
	fprintf(stdout, "                                       [-f config] [-P pidfile] [-b path]\n");
	fprintf(stdout, "                                       [-R] [-D]\n");
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
		case SIGHUP:
		case SIGTERM:
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
read_mailertable(short int iprefer)
{
	FILE *fh;
	struct doment *domadd;
	char line[LINELENGTH + 1];
	char buf[LINELENGTH + 1];
	char *token;

	if ((fh = fopen( mailertable, "r")) == NULL) {
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
			syslog (LOG_DEBUG, "BackAddrDomain %s", buf);

			token = strtok(line, "[");
			if (token != NULL)
			{
				token = strtok(NULL, "[");

				if (token != NULL)
				{
					if (sscanf( token, "%256[A-Za-z0-9-.]", buf) == 1)
					{
						struct sockaddr_storage ss;
						int e = hostss(buf, &ss, iprefer);
						if (e != 0)
						{
							memcpy(&domadd->backss, &ss, sizeof(ss));
							domadd->backsmtpport = backsmtpport;
							syslog (LOG_INFO, "BackSMTPServer %s", buf);

#ifdef FALLBACKEND
							token = strtok(NULL, "[");

							if (token != NULL)
							{
								if (sscanf( token, "%256[A-Za-z0-9-.]", buf) == 1)
								{
									struct sockaddr_storage ss;
									int e = hostss(buf, &ss, iprefer);
									if (e != 0)
									{
										memcpy(&domadd->backss2, &ss, sizeof(ss));
										domadd->backsmtpport2 = backsmtpport;
										syslog (LOG_INFO, "BackSMTPServer %s", buf);
									} else {
										syslog (LOG_ERR, "BackSMTPServer %s incorrect %s", buf, gai_strerror(e) );
										fclose(fh);
										return 1;
									}
								}
							}
#endif /* FALLBACKEND */
							SLIST_INSERT_HEAD(&domlist, domadd, domentries);
						} else {
							syslog (LOG_ERR, "BackSMTPServer %s incorrect %s", buf, gai_strerror(e) );
							fclose(fh);
							return 1;
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
	short int iprefer = 0;
	int lline;
	int lineno = 0;
	int e = -10;
	char line[LINELENGTH + 1];
	char buf[LINELENGTH + 1];
#ifndef USEMAILERTABLE
	struct doment *domadd;
#endif

#ifndef ALLDOMAINS
	struct sockaddr_storage curss;
#else
	memset((void *) &backss, 0, sizeof(struct sockaddr_storage));
#endif

#ifdef BITBUCKET
	syslog (LOG_INFO, "bitbucket enabled");
#endif
	if ((fh = fopen( conf, "r")) == NULL)
		return 1;

	while( fgets(line, LINELENGTH, fh) )
	{
		lineno++;
		if (line[0] == '#')
			continue;

		lline = strlen(line);
		if (lline > 16)
		{
			unsigned int ip1 = 0;
			unsigned int ip2 = 0;
			unsigned int ip3 = 0;
			unsigned int ip4 = 0;
			unsigned int ipm = 0;
			struct CIDR *entcidr;

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
#ifdef USEMAILERTABLE
			else if (sscanf( line, "Mailertable:%256[^\n]", buf) == 1)
			{
				if (strlen(buf) > 6)
				{
					if (mailertable == NULL)
					{
						mailertable = strdup(buf);
						syslog (LOG_DEBUG, "Mailertable set to %s", mailertable);
					}
				}
			}
#else
			else if (sscanf( line, "BackSMTPServer:%255[A-Za-z0-9-.:]", buf) == 1)
			{
				if (strlen(buf) > 6)
				{
					struct sockaddr_storage ss;
					e = hostss(buf, &ss, iprefer);
					if (e == 0)
					{
#ifdef ALLDOMAINS
						memcpy(&backss, &ss, sizeof(ss));
					} else {
						syslog (LOG_ERR, "BackSMTPServer incorrect %s %s", buf, gai_strerror(e));
						exit(EX_OSERR);
					}
#else
						memcpy(&curss, &ss, sizeof(ss));
					} else {
						syslog (LOG_ERR, "BackSMTPServer incorrect %s %s", buf, gai_strerror(e));
						exit(EX_OSERR);
					}
#endif /* ALLDOMAINS */
					syslog (LOG_DEBUG, "BackSMTPServer %s", buf);
				}
			}
			else if (sscanf( line, "BackAddrDomain:%256[A-Za-z0-9-.]", buf) == 1)
			{
				if (strlen(buf) > 3)
				{
					domadd = (struct doment *)malloc(sizeof(struct doment));
#ifndef ALLDOMAINS
					if (e != 0)
					{
						syslog (LOG_ERR, "BackSMTPServer should be defined before BackAddrDomain");
						exit(EX_OSERR);
					}

					memcpy(&domadd->backss, &curss, sizeof(curss));
					domadd->backsmtpport = backsmtpport;
#endif /* ALLDOMAINS */
					if ((domadd->domain = strdup(buf)) == NULL)
					{
						return 1;
					}
					SLIST_INSERT_HEAD(&domlist, domadd, domentries);
					syslog (LOG_DEBUG, "BackAddrDomain %s", buf);
				}
			}
#endif /* USEMAILERTABLE */
			else if (sscanf( line, "BackSMTPPort:%5[0-9]", buf) == 1)
			{
				int num;

				num = atoi(buf);
				if (num > 0)
					backsmtpport = num;

				syslog (LOG_DEBUG, "BackSMTPPort set to %d", backsmtpport);
			}
			else if (sscanf( line, "PreferIPVersion:%1[0-9]", buf) == 1)
			{
				int num;

				num = atoi(buf);
				if (num >= 0)
					iprefer = num;

				syslog (LOG_DEBUG, "PreferIPVersion set to %d", iprefer);
			}
			else if (sscanf( line, "BackAddrSubdomains:%3[a-zA-Z]", buf) == 1)
			{
				if (strcasecmp("yes", buf) == 0)
				{
					addrsubdomain = 1;
					syslog (LOG_DEBUG, "BackAddrSubdomains %s", buf);
				}
			}
			else if (sscanf( line, "BackErrorTempfail:%3[a-zA-Z]", buf) == 1)
			{
				if (strcasecmp("yes", buf) == 0)
				{
					backerrfail = 1;
					syslog (LOG_DEBUG, "BackErrorTempfail %s", buf);
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
			else if (sscanf( line, "TimeoutSMTPConnect:%4[0-9]", buf) == 1)
			{
				int num;

				num = atoi(buf);
				if (num > 0)
				{
					syslog (LOG_DEBUG, "TimeoutSMTPConnect set to %d seconds", num);
					timeoutconnect = num * 1000;
				}
			}
			else if (sscanf( line, "TimeoutSMTPReply:%5[0-9]", buf) == 1)
			{
				int num;

				num = atoi(buf);
				if (num > 0)
					timeoutreply = num;

				syslog (LOG_DEBUG, "TimeoutSMTPReply set to %d seconds", timeoutreply);
			}
			else if (sscanf( line, "BackSkipVerify:%u.%u.%u.%u/%u", &ip1, &ip2, &ip3, &ip4, &ipm) == 5)
			{
				snprintf( buf, sizeof(buf), "%u.%u.%u.%u", ip1, ip2, ip3, ip4);
				entcidr = (struct CIDR *)malloc(sizeof(struct CIDR));
				entcidr->ip = inet_addr(buf);
				entcidr->masklen = ipm;
				SLIST_INSERT_HEAD(&backcidr, entcidr, cidrs);
				syslog (LOG_DEBUG, "BackSkipVerify set %s/%d", buf, ipm);
			}
			else if (sscanf( line, "BackSkipVerify:%u.%u.%u.%u", &ip1, &ip2, &ip3, &ip4) == 4)
			{
				snprintf( buf, sizeof(buf), "%u.%u.%u.%u", ip1, ip2, ip3, ip4);
				entcidr = (struct CIDR *)malloc(sizeof(struct CIDR));
				entcidr->ip = inet_addr(buf);
				entcidr->masklen = 32;
				SLIST_INSERT_HEAD(&backcidr, entcidr, cidrs);
				syslog (LOG_DEBUG, "BackSkipVerify set %s", buf);
			}
			else if (sscanf( line, "BackSkipDaemon:%256[A-Za-z0-9-.]", buf) == 1)
			{
				if (strlen(buf) > 0)
				{
					struct entry *daemonadd;
					daemonadd = (struct entry *)malloc(sizeof(struct entry));
					if ((daemonadd->c = strdup(buf)) == NULL)
					{
						return 1;
					}
					SLIST_INSERT_HEAD(&daemonlist, daemonadd, entries);
					syslog (LOG_DEBUG, "BackSkipDaemon %s", buf);
				}
			}
			else if (sscanf( line, "BackSMTPBackoff:%5[0-9]", buf) == 1)
			{
				int num;

				num = atoi(buf);
				if (num > 0)
					backsmtpbackoff = num;

				syslog (LOG_DEBUG, "BackSMTPBackoff set to %d seconds", timeoutreply);
			}
		}
	}
	fclose(fh);

#ifdef USEMAILERTABLE
	if (mailertable == NULL)
		mailertable = strdup(DEFMAILERTABLE);
	read_mailertable(iprefer);

	free(mailertable);
#endif

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
	const char *args = "p:T:u:f:g:b:P:Dhv";
	extern char *optarg;
	struct passwd *passwd = NULL;
	struct group *grp;
	char *user = NULL;
	char *group = NULL;
	uid_t uid = 0;
	gid_t gid = 0;
	char *conf = NULL;
	char *pidfile =NULL;
	int daemonmode = 0;
	struct CIDR *entcidr;

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
#ifndef HELOHOST
	memset(hostname, '\0', sizeof hostname);
	if (gethostname(hostname, sizeof hostname) != 0)
	{
		fprintf(stderr, "gethostname failed\n");
		syslog (LOG_ERR, "gethostname failed");
		exit(EX_UNAVAILABLE);
	}
#else
	snprintf( hostname, MAXHOSTNAMELEN, "%s", HELOHOST);
#endif /* HELOHOST */

	SLIST_INIT( &domlist);
	SLIST_INIT( &backcidr);
	SLIST_INIT( &daemonlist);

	if (conf == NULL)
		conf = strdup(SCAMCONF);

	back_readconf(conf);
	free(conf);

	entcidr = (struct CIDR *)malloc(sizeof(struct CIDR));
	entcidr->ip = inet_addr("127.0.0.1");
	entcidr->masklen = 32;
	SLIST_INSERT_HEAD(&backcidr, entcidr, cidrs);
	syslog (LOG_DEBUG, "BackSkipVerify set 127.0.0.1");

	if (SLIST_EMPTY(&daemonlist))
	{
		struct entry *daemonadd;
		daemonadd = (struct entry *)malloc(sizeof(struct entry));
		if ((daemonadd->c = strdup("MSA")) == NULL)
		{
			exit(EX_OSERR);
		}
		SLIST_INSERT_HEAD(&daemonlist, daemonadd, entries);
		syslog (LOG_DEBUG, "BackSkipDaemon MSA");
	}

#ifdef ALLDOMAINS
	if (backss.ss_len == 0)
	{
		syslog (LOG_ERR, "BackSMTPServer not defined");
		exit(EX_OSERR);
	}
#else
	if (SLIST_EMPTY(&domlist))
	{
		syslog (LOG_ERR, "BackAddrDomain not defined");
		exit(EX_OSERR);
	}
#endif /* ALLDOMAINS */
	TAILQ_INIT(&backhead);

	if ((ret = pthread_rwlock_init(&back_lock, NULL)) != 0)
	{
		syslog(LOG_ERR,  "pthread_rwlock_init failed: %s", strerror(ret));
		exit(EX_OSERR);
	}

	if ((ret = pthread_rwlock_init(&skipvrfy_lock, NULL)) != 0)
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

