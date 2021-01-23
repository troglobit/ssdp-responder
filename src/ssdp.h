/* SSDP responder
 *
 * Copyright (c) 2017-2021  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.a
 */
#ifndef SSDP_H_
#define SSDP_H_

#include "config.h"
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <paths.h>
#include <poll.h>
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/param.h>		/* MIN() */
#include <sys/socket.h>
#include <syslog.h>

#include "compat.h"
#include "queue.h"

/* Notify should be less than half the cache timeout */
#define NOTIFY_INTERVAL      300
#define REFRESH_INTERVAL     600
#define CACHE_TIMEOUT        1800
#define MAX_NUM_IFACES       100
#define MAX_PKT_SIZE         2000
#define MC_SSDP_GROUP        "239.255.255.250"
#define MC_SSDP_PORT         1900
#define MC_TTL_DEFAULT       2
#ifndef TEST_MODE
# define LOCATION_PORT       (MC_SSDP_PORT + 1)
#else
# define LOCATION_PORT       8080
#endif
#define LOCATION_DESC        "/description.xml"

#define SSDP_ST_ALL          "ssdp:all"

#define ENABLE_SOCKOPT(sd, level, opt)					\
        do {								\
                int val = 1;						\
		if (setsockopt(sd, level, opt, &val, sizeof(val)) < 0)	\
			warn("Failed enabling %s", #opt);		\
        } while (0);

/* From The Practice of Programming, by Kernighan and Pike */
#ifndef NELEMS
#define NELEMS(array) (sizeof(array) / sizeof(array[0]))
#endif

struct ifsock {
	LIST_ENTRY(ifsock) link;

	int stale;
	int mod;

	/* Interface socket, one per interface address */
	int sd;

	/* Interface address and netmask */
	struct sockaddr_in addr;
	struct sockaddr_in mask;

	void (*cb)(int);
};

extern int log_level;
extern int log_opts;

void log_init(int enable);
void log_exit(void);
int log_str2lvl(char *level);
void logit(int severity, const char *format, ...);

struct ifsock *ssdp_find(struct sockaddr *sa);
void ssdp_foreach(void (*cb)(struct ifsock *, int), int arg);

int ssdp_init(int ttl, int srv, char *iflist[], size_t num, void (*cb)(int sd));
int ssdp_exit(void);

int ssdp_register(int sd, struct sockaddr *addr, struct sockaddr *mask, void (*cb)(int sd));
int ssdp_poll(int timeout);

#endif /* SSDP_H_ */
