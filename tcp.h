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

#ifndef ES_TCP_H_
#define ES_TCP_H_

int waitconnect(int, int);
int clientconn(int *, struct sockaddr_storage, short int, unsigned int);
int clientread(int , char** buffer, size_t , unsigned int);
int clientwrite(int, char* , int);

#endif /* ES_TCP_H_ */


