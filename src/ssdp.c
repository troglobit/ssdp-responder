/* SSDP helper functions
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

#define SYSLOG_NAMES
#include <stdarg.h>
#include "ssdp.h"

LIST_HEAD(, ifsock) il = LIST_HEAD_INITIALIZER();

int log_level = LOG_NOTICE;
int log_opts  = LOG_PID;
int log_on    = 1;

void log_init(int enable)
{
	if (!enable) {
		log_on = 0;
		return;
	}

        openlog(PACKAGE_NAME, log_opts, LOG_DAEMON);
        setlogmask(LOG_UPTO(log_level));
}

void log_exit(void)
{
	if (!log_on)
		return;
	closelog();
}

int log_str2lvl(char *level)
{
    int i;

    for (i = 0; prioritynames[i].c_name; i++) {
	size_t len = MIN(strlen(prioritynames[i].c_name), strlen(level));

	if (!strncasecmp(prioritynames[i].c_name, level, len))
	    return prioritynames[i].c_val;
    }

    return atoi(level);
}

void logit(int severity, const char *format, ...)
{
	va_list ap;

	if (severity > log_level)
		return;

	va_start(ap, format);
	if (!log_on) {
		vfprintf(stderr, format, ap);
		fputs("\n", stderr);
	} else
		vsyslog(severity, format, ap);
	va_end(ap);
}

static void mark(void)
{
	struct ifsock *ifs;

	LIST_FOREACH(ifs, &il, link) {
		in_addr_t a, m;

		a = ifs->addr.sin_addr.s_addr;
		m = ifs->mask.sin_addr.s_addr;
		if (a == htonl(INADDR_ANY) || m == htonl(INADDR_ANY))
			continue;

		if (ifs->sd != -1)
			ifs->stale = 1;
		else
			ifs->stale = 0;
	}
}

static int sweep(void)
{
	struct ifsock *ifs, *tmp;
	int modified = 0;

	LIST_FOREACH_SAFE(ifs, &il, link, tmp) {
		if (!ifs->stale)
			continue;

		modified++;
		logit(LOG_DEBUG, "Removing stale ifs %s", inet_ntoa(ifs->addr.sin_addr));

		LIST_REMOVE(ifs, link);
		close(ifs->sd);
		free(ifs);
	}

	return modified;
}

/* Find interface in same subnet as sa */
struct ifsock *ssdp_find(struct sockaddr *sa)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)sa;
	struct ifsock *ifs;
	in_addr_t cand;

	cand = addr->sin_addr.s_addr;
	LIST_FOREACH(ifs, &il, link) {
		in_addr_t a, m;

		a = ifs->addr.sin_addr.s_addr;
		m = ifs->mask.sin_addr.s_addr;
		if (a == htonl(INADDR_ANY) || m == htonl(INADDR_ANY))
			continue;

		if ((a & m) == (cand & m))
			return ifs;
	}

	return NULL;
}

/* Exact match, must be same ifaddr as sa */
static struct ifsock *find_iface(struct sockaddr *sa)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)sa;
	struct ifsock *ifs;

	if (!sa)
		return NULL;

	LIST_FOREACH(ifs, &il, link) {
		if (ifs->addr.sin_addr.s_addr == addr->sin_addr.s_addr)
			return ifs;
	}

	return NULL;
}

static int filter_addr(struct sockaddr *sa)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct ifsock *ifs;

	if (!sa)
		return 1;

	if (sa->sa_family != AF_INET)
		return 1;

	if (sin->sin_addr.s_addr == htonl(INADDR_ANY))
		return 1;

#ifndef TEST_MODE
	if (sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
		return 1;
#endif

	ifs = ssdp_find(sa);
	if (ifs) {
		if (ifs->addr.sin_addr.s_addr != htonl(INADDR_ANY))
			return 1;
	}

	return 0;
}

static int filter_iface(char *ifname, char *iflist[], size_t num)
{
	size_t i;

	if (!num) {
		logit(LOG_DEBUG, "No interfaces to filter, using all with an IP address.");
		return 0;
	}

	logit(LOG_DEBUG, "Filter %s?  Comparing %zd entries ...", ifname, num);
	for (i = 0; i < num; i++) {
		logit(LOG_DEBUG, "Filter %s?  Comparing with %s ...", ifname, iflist[i]);
		if (!strcmp(ifname, iflist[i]))
			return 0;
	}

	return 1;
}

static void handle_message(int sd)
{
	struct ifsock *ifs;

	LIST_FOREACH(ifs, &il, link) {
		if (ifs->sd != sd)
			continue;

		if (ifs->cb)
			ifs->cb(sd);
	}
}

int ssdp_poll(int timeout)
{
	struct pollfd pfd[MAX_NUM_IFACES];
	struct ifsock *ifs;
	size_t ifnum = 0;
	int num;

	LIST_FOREACH(ifs, &il, link) {
		pfd[ifnum].fd     = ifs->sd;
		pfd[ifnum].events = POLLIN;
		ifnum++;
	}

	num = poll(pfd, ifnum, timeout);
	if (num < 0)
		return -1;
	if (num == 0)
		return 0;

	for (size_t i = 0; i < ifnum; i++) {
		if (pfd[i].revents & POLLNVAL ||
		    pfd[i].revents & POLLHUP)
			continue;

		if (pfd[i].revents & POLLIN)
			handle_message(pfd[i].fd);
	}

	return num;
}

int ssdp_register(int sd, struct sockaddr *addr, struct sockaddr *mask, void (*cb)(int sd))
{
	struct sockaddr_in *address = (struct sockaddr_in *)addr;
	struct sockaddr_in *netmask = (struct sockaddr_in *)mask;
	struct ifsock *ifs;

	ifs = calloc(1, sizeof(*ifs));
	if (!ifs) {
		char *host = inet_ntoa(address->sin_addr);

		logit(LOG_ERR, "Failed registering host %s socket: %s", host, strerror(errno));
		return -1;
	}

	ifs->sd   = sd;
	ifs->mod  = 1;
	ifs->cb   = cb;
	if (address)
		ifs->addr = *address;
	if (mask)
		ifs->mask = *netmask;
	LIST_INSERT_HEAD(&il, ifs, link);

	return 0;
}

void ssdp_foreach(void (*cb)(struct ifsock *, int), int arg)
{
	struct ifsock *ifs;

	LIST_FOREACH(ifs, &il, link)
		cb(ifs, arg);
}

static int socket_open(char *ifname, struct sockaddr *addr, int ttl, int srv)
{
	struct sockaddr_in sin, *address = (struct sockaddr_in *)addr;
	int sd, rc;

	sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sd < 0)
		return -1;

        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEADDR);
#ifdef SO_REUSEPORT
        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEPORT);
#endif

	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	if (rc < 0) {
		close(sd);
		logit(LOG_ERR, "Failed setting multicast TTL: %s", strerror(errno));
		return -1;
	}

	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &address->sin_addr, sizeof(address->sin_addr));
	if (rc < 0) {
		close(sd);
		logit(LOG_ERR, "Failed setting multicast interface: %s", strerror(errno));
		return -1;
	}

	logit(LOG_DEBUG, "Adding new interface %s with address %s", ifname, inet_ntoa(address->sin_addr));
	if (!srv)
		return sd;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(MC_SSDP_PORT);
	sin.sin_addr.s_addr = inet_addr("0.0.0.0");
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		logit(LOG_ERR, "Failed binding to %s:%d: %s", inet_ntoa(address->sin_addr),
 		      MC_SSDP_PORT, strerror(errno));
	}

	return sd;
}

int ssdp_exit(void)
{
	struct ifsock *ifs, *tmp;
	int ret = 0;

	LIST_FOREACH_SAFE(ifs, &il, link, tmp) {
		LIST_REMOVE(ifs, link);
		if (ifs->sd != -1)
			ret |= close(ifs->sd);
		free(ifs);
	}

	return ret;
}

/*
 * This one differs between BSD and Linux in that on BSD this
 * disables looping multicast back to all *other* sockets on
 * this machine.  Whereas Linux only disables looping it on
 * the given socket ... please prove me wrong.  --Troglobit
 */
static void multicast_loop(int sd)
{
	char loop = 0;
	int rc;

	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	if (rc < 0)
		logit(LOG_WARNING, "Failed disabing multicast loop: %s", strerror(errno));
}

static int multicast_join(int sd, struct sockaddr *sa)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct ip_mreq imr;

	imr.imr_interface = sin->sin_addr;
	imr.imr_multiaddr.s_addr = inet_addr(MC_SSDP_GROUP);
        if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(imr))) {
		if (EADDRINUSE == errno)
			return 0;

		logit(LOG_ERR, "Failed joining group %s: %s", MC_SSDP_GROUP, strerror(errno));
		return -1;
	}

	return 0;
}

int ssdp_init(int ttl, int srv, char *iflist[], size_t num, void (*cb)(int sd))
{
	struct ifaddrs *ifaddrs, *ifa;
	int modified;
	size_t i;

	logit(LOG_INFO, "Updating interfaces ...");

	if (getifaddrs(&ifaddrs) < 0) {
		logit(LOG_ERR, "Failed getifaddrs(): %s", strerror(errno));
		return -1;
	}

	/* Mark all outbound interfaces as stale */
	mark();

	/* First pass, clear stale marker from exact matches */
	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		struct ifsock *ifs;

		/* Do we already have it? */
		ifs = find_iface(ifa->ifa_addr);
		if (ifs) {
			ifs->stale = 0;
			continue;
		}
	}

	/* Clean out any stale interface addresses */
	modified = sweep();

	/* Second pass, add new ones */
	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		int sd;

		/* Interface filtering, optional command line argument */
		if (filter_iface(ifa->ifa_name, iflist, num)) {
			logit(LOG_DEBUG, "Skipping %s, not in iflist.", ifa->ifa_name);
			continue;
		}

		/* Do we have another in the same subnet? */
		if (filter_addr(ifa->ifa_addr))
			continue;

		sd = socket_open(ifa->ifa_name, ifa->ifa_addr, ttl, srv);
		if (sd < 0)
			continue;

#ifdef __linux__
		multicast_loop(sd);
#endif

		if (!multicast_join(sd, ifa->ifa_addr))
			logit(LOG_DEBUG, "Joined group %s on interface %s", MC_SSDP_GROUP, ifa->ifa_name);

		if (ssdp_register(sd, ifa->ifa_addr, ifa->ifa_netmask, cb)) {
			close(sd);
			break;
		}

		logit(LOG_DEBUG, "Registered socket %d with ssd_recv() callback", sd);
		modified++;
	}

	freeifaddrs(ifaddrs);

	return modified;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
