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

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "util.h"

char* rfc822domain( char* rfc822addr )
{
	char *p = rfc822addr;
	char *q;
	int k;

	k = strlen( p );

	if ( k >= 1 )
	{
		for ( q = p + k - 1; q != p; --q )
		{
			if ( *(q - 1) == '@' )
			{
				p = q;
				break;
			}
		}
	}

	return p;
}

unsigned int hostin_addr( char *host) {
	unsigned char dnsreply[PACKETSZ];
	char expdn[PACKETSZ];
	unsigned char *p;
	HEADER *dnsheader;
	int ret = 0;
	int dxp, i;
	unsigned int ttl;
	struct in_addr inaddr;

	ret = inet_pton(AF_INET, host, &inaddr);
	if (ret == 1)
		return inaddr.s_addr;

	if (res_init() == -1)
		return 0;

	memset( dnsreply, '\0', sizeof( dnsreply ));

	ret = res_query( host, C_IN, T_A, dnsreply, sizeof( dnsreply ));

	if (ret == -1)
		return 0;

	dnsheader = (HEADER *) &dnsreply;
	if (dnsheader->rcode == 0) {
		p = dnsreply +sizeof(HEADER);

		if((dxp = dn_expand(dnsreply, dnsreply + ret, p, expdn, PACKETSZ)) < 0) {
			return 0;
		}

		p += dxp;

		GETSHORT(i, p);
		if (i != T_A)
			return 0;

		p += INT16SZ;


		if((dxp = dn_expand(dnsreply, dnsreply + ret, p, expdn, PACKETSZ)) < 0) {
			return 0;
		}

		p += dxp;

		GETSHORT(i, p);
		if (i != T_A)
			return 0;

		p += INT16SZ;

		GETLONG(ttl, p);
		GETSHORT(i, p);

		if (i == 4)
		{
			memcpy( (char *)&inaddr, p, INADDRSZ);
			return inaddr.s_addr;
		}
	}

	return 0;
}

