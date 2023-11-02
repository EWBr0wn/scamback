/*
Copyright © 2004 Eland Systems All Rights Reserved.

   1. Redistribution and use in source and binary forms must retain the above
   copyright notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   3. The name of Eland Systems may not be used to endorse or promote products
   derived from this software without specific prior written permission.

 *
 * Locking management Copyright (c) 2004 Emmanuel Dreyfus
 */

#define WRLOCK(lock) {							  \
	int err;							  \
									  \
	if ((err = pthread_rwlock_wrlock(&(lock))) != 0) {		  \
		syslog(LOG_ERR, "%s:%d pthread_rwlock_wrlock failed: %s", \
		    __FILE__, __LINE__, strerror(err));			  \
		exit(EX_SOFTWARE);					  \
	}								  \
}

#define RDLOCK(lock) {							  \
	int err;							  \
									  \
	if ((err = pthread_rwlock_rdlock(&(lock))) != 0) {		  \
		syslog(LOG_ERR, "%s:%d pthread_rwlock_rdlock failed: %s", \
		    __FILE__, __LINE__, strerror(err));			  \
		exit(EX_SOFTWARE);					  \
	}								  \
}

/*
 * There is a bug in GNU pth-2.0.0 that will cause a spurious EPERM
 * error when a thread releases a read lock that has been shared by
 * two threads and already released by the other one. As a workaround
 * for that problem, we just avoid quitting on this error.
 */
#ifndef HAVE_BROKEN_RWLOCK
#define UNLOCK(lock) {							  \
	int err;							  \
									  \
	if ((err = pthread_rwlock_unlock(&(lock))) != 0) {		  \
		syslog(LOG_ERR, "%s:%d pthread_rwlock_unlock failed: %s", \
		    __FILE__, __LINE__, strerror(err));			  \
		exit(EX_SOFTWARE);					  \
	}								  \
}
#else
#define UNLOCK(lock) {							  \
	int err;							  \
									  \
	if ((err = pthread_rwlock_unlock(&(lock))) != 0) {		  \
		syslog(LOG_DEBUG, "%s:%d pthread_rwlock_unlock failed: "  \
		    "%s (ignored)", __FILE__, __LINE__, strerror(err));	  \
	}								  \
}
#endif

/*
 * Some systems don't know about LOG_PERROR. By defining it
 * to zero, we make it nilpotent
 */
#ifdef HAVE_MISSING_LOG_PERROR
#define LOG_PERROR 0
#endif

#ifdef HAVE_MISSING_TIMERADD
#define	timeradd(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;	\
		if ((vvp)->tv_usec >= 1000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (/* CONSTCOND */ 0)
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (/* CONSTCOND */ 0)
#endif

