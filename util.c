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

int hostss(char* host, struct sockaddr_storage *ss, short int iprefer)
{
	int ret;
	struct addrinfo hints, *ai;

	memset(&hints, 0, sizeof(hints));
	switch (iprefer)
	{
		case 4:
			hints.ai_family = PF_INET;
			break;
		case 6:
			hints.ai_family = PF_INET6;
			break;

		default:
			hints.ai_family = PF_UNSPEC;
			break;
	}

	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(host, "smtp", &hints, &ai);
	if (ret != 0)
		return ret;

	memcpy( ss, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);

	return 0;
}
