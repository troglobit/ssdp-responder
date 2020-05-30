/* SSDP responder
 *
 * Copyright (c) 2017-2019  Joachim Nilsson <troglobit@gmail.com>
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

#include "ssdp.h"
#include "queue.h"

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

LIST_HEAD(, ifsock) il = LIST_HEAD_INITIALIZER();

static char *supported_types[] = {
	SSDP_ST_ALL,
	"upnp:rootdevice",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	uuid,
	NULL
};

int      debug = 0;
int      running = 1;

char uuid[42];
char hostname[64];
char *os = NULL, *ver = NULL;
char server_string[64] = "POSIX UPnP/1.0 " PACKAGE_NAME "/" PACKAGE_VERSION;

/* Find interface in same subnet as sa */
static struct ifsock *find_outbound(struct sockaddr *sa)
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

int register_socket(int sd, struct sockaddr *addr, struct sockaddr *mask, void (*cb)(int sd))
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
	ifs->addr = *address;
	if (mask)
		ifs->mask = *netmask;
	LIST_INSERT_HEAD(&il, ifs, link);

	return 0;
}

static int open_socket(char *ifname, struct sockaddr *addr, int port, int ttl)
{
	struct sockaddr_in sin, *address = (struct sockaddr_in *)addr;
	struct ip_mreqn mreq;
	int sd, rc;
	char loop;

	sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sd < 0)
		return -1;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr(MC_SSDP_GROUP);
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(sd);
		logit(LOG_ERR, "Failed binding to %s:%d: %s", inet_ntoa(address->sin_addr), port, strerror(errno));
		return -1;
	}

        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEADDR);
#ifdef SO_REUSEPORT
        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEPORT);
#endif

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_address = address->sin_addr;
	mreq.imr_multiaddr.s_addr = inet_addr(MC_SSDP_GROUP);
        if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		close(sd);
		logit(LOG_ERR, "Failed joining group %s: %s", MC_SSDP_GROUP, strerror(errno));
		return -1;
	}

	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	if (rc < 0) {
		close(sd);
		logit(LOG_ERR, "Failed setting multicast TTL: %s", strerror(errno));
		return -1;
	}

	loop = 0;
	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	if (rc < 0) {
		close(sd);
		logit(LOG_ERR, "Failed disabing multicast loop: %s", strerror(errno));
		return -1;
	}

	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &address->sin_addr, sizeof(address->sin_addr));
	if (rc < 0) {
		close(sd);
		logit(LOG_ERR, "Failed setting multicast interface: %s", strerror(errno));
		return -1;
	}

	logit(LOG_DEBUG, "Adding new interface %s with address %s", ifname, inet_ntoa(address->sin_addr));

	return sd;
}

static int close_socket(void)
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

	if (sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
		return 1;

	ifs = find_outbound(sa);
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

static void compose_addr(struct sockaddr_in *sin, char *group, int port)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family      = AF_INET;
	sin->sin_port        = htons(port);
	sin->sin_addr.s_addr = inet_addr(group);
}

static void compose_response(char *type, char *host, char *buf, size_t len)
{
	char usn[256];
	char date[42];
	time_t now;

	/* RFC1123 date, as specified in RFC2616 */
	now = time(NULL);
	strftime(date, sizeof(date), "%a, %d %b %Y %T %Z", gmtime(&now));

	if (type) {
		if (!strcmp(type, uuid))
			type = NULL;
		else
			snprintf(usn, sizeof(usn), "%s::%s", uuid, type);
	}

	if (!type)
		strlcpy(usn, uuid, sizeof(usn));

	snprintf(buf, len, "HTTP/1.1 200 OK\r\n"
		 "Server: %s\r\n"
		 "Date: %s\r\n"
		 "Location: http://%s:%d%s\r\n"
		 "ST: %s\r\n"
		 "EXT: \r\n"
		 "USN: %s\r\n"
		 "Cache-Control: max-age=%d\r\n"
		 "\r\n",
		 server_string,
		 date,
		 host, LOCATION_PORT, LOCATION_DESC,
		 type,
		 usn,
		 CACHE_TIMEOUT);
}

static void compose_notify(char *type, char *host, char *buf, size_t len)
{
	char usn[256];

	if (type) {
		if (!strcmp(type, SSDP_ST_ALL))
			type = NULL;
		else
			snprintf(usn, sizeof(usn), "%s::%s", uuid, type);
	}

	if (!type) {
		type = usn;
		strlcpy(usn, uuid, sizeof(usn));
	}

	snprintf(buf, len, "NOTIFY * HTTP/1.1\r\n"
		 "Host: %s:%d\r\n"
		 "Server: %s\r\n"
		 "Location: http://%s:%d%s\r\n"
		 "NT: %s\r\n"
		 "NTS: ssdp:alive\r\n"
		 "USN: %s\r\n"
		 "Cache-Control: max-age=%d\r\n"
		 "\r\n",
		 MC_SSDP_GROUP, MC_SSDP_PORT,
		 server_string,
		 host, LOCATION_PORT, LOCATION_DESC,
		 type,
		 usn,
		 CACHE_TIMEOUT);
}

size_t pktlen(unsigned char *buf)
{
	size_t hdr = sizeof(struct udphdr);

	return strlen((char *)buf + hdr) + hdr;
}

static void send_message(struct ifsock *ifs, char *type, struct sockaddr *sa)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct sockaddr dest;
	char host[NI_MAXHOST];
	char buf[MAX_PKT_SIZE];
	size_t i, len, note = 0;
	ssize_t num;
	int s;

	gethostname(hostname, sizeof(hostname));
	s = getnameinfo((struct sockaddr *)&ifs->addr, sizeof(struct sockaddr_in), host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	if (s) {
		logit(LOG_WARNING, "Failed getnameinfo(): %s", gai_strerror(s));
		return;
	}

	if (ifs->addr.sin_addr.s_addr == htonl(INADDR_ANY))
		return;

	if (!strcmp(type, SSDP_ST_ALL))
		type = NULL;

	memset(buf, 0, sizeof(buf));
	if (sin)
		compose_response(type, host, buf, sizeof(buf));
	else
		compose_notify(type, host, buf, sizeof(buf));

	if (!sin) {
		note = 1;
		compose_addr((struct sockaddr_in *)&dest, MC_SSDP_GROUP, MC_SSDP_PORT);
		sin = (struct sockaddr_in *)&dest;
	}

	logit(LOG_DEBUG, "Sending %s from %s ...", !note ? "reply" : "notify", host);
	num = sendto(ifs->sd, buf, strlen(buf), 0, (struct sockaddr *)sin, sizeof(struct sockaddr_in));
	if (num < 0)
		logit(LOG_WARNING, "Failed sending SSDP %s, type: %s: %s", !note ? "reply" : "notify", type, strerror(errno));
}

static void ssdp_recv(int sd)
{
	char buf[MAX_PKT_SIZE + 1];
	struct sockaddr sa;
	socklen_t salen;
	ssize_t len;

	memset(buf, 0, sizeof(buf));
	salen = sizeof(sa);
	len = recvfrom(sd, buf, sizeof(buf) - 1, MSG_DONTWAIT, &sa, &salen);
	if (len > 0) {
		buf[len] = 0;

		if (sa.sa_family != AF_INET)
			return;

		if (strstr(buf, "M-SEARCH *")) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
			struct ifsock *ifs;
			char *ptr, *type;
			size_t i;

			ifs = find_outbound(&sa);
			if (!ifs) {
				logit(LOG_DEBUG, "No matching socket for client %s", inet_ntoa(sin->sin_addr));
				return;
			}
			logit(LOG_DEBUG, "Matching socket for client %s", inet_ntoa(sin->sin_addr));

			type = strcasestr(buf, "\r\nST:");
			if (!type) {
				logit(LOG_DEBUG, "No Search Type (ST:) found in M-SEARCH *, assuming " SSDP_ST_ALL);
				type = SSDP_ST_ALL;
				send_message(ifs, type, &sa);
				return;
			}

			type = strchr(type, ':');
			if (!type)
				return;
			type++;
			while (isspace(*type))
				type++;

			ptr = strstr(type, "\r\n");
			if (!ptr)
				return;
			*ptr = 0;

			for (i = 0; supported_types[i]; i++) {
				if (!strcmp(supported_types[i], type)) {
					logit(LOG_DEBUG, "M-SEARCH * ST: %s from %s port %d", type,
					      inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
					send_message(ifs, type, &sa);
					return;
				}
			}

			logit(LOG_DEBUG, "M-SEARCH * for unsupported ST: %s from %s", type,
			      inet_ntoa(sin->sin_addr));
		}
	}
}

static int multicast_join(int sd, struct sockaddr *sa)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct ip_mreqn imr;

	memset(&imr, 0, sizeof(imr));
	imr.imr_address = sin->sin_addr;
	imr.imr_multiaddr.s_addr = inet_addr(MC_SSDP_GROUP);
        if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(imr))) {
		if (EADDRINUSE == errno)
			return 0;

		logit(LOG_ERR, "Failed joining group %s: %s", MC_SSDP_GROUP, strerror(errno));
		return -1;
	}

	return 0;
}

static void mark(void)
{
	struct ifsock *ifs;

	LIST_FOREACH(ifs, &il, link) {
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

static int ssdp_init(int ttl, char *iflist[], size_t num)
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

		sd = open_socket(ifa->ifa_name, ifa->ifa_addr, MC_SSDP_PORT, ttl);
		if (sd < 0)
			continue;

		if (!multicast_join(sd, ifa->ifa_addr))
			logit(LOG_DEBUG, "Joined group %s on interface %s", MC_SSDP_GROUP, ifa->ifa_name);

		if (register_socket(sd, ifa->ifa_addr, ifa->ifa_netmask, ssdp_recv)) {
			close(sd);
			break;
		}
		logit(LOG_DEBUG, "Registered socket %d with ssd_recv() callback", sd);
		modified++;
	}

	freeifaddrs(ifaddrs);

	return modified;
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

static void wait_message(time_t tmo)
{
	struct pollfd pfd[MAX_NUM_IFACES];
	struct ifsock *ifs;
	int num = 1, timeout;
	size_t ifnum = 0;

	LIST_FOREACH(ifs, &il, link) {
		pfd[ifnum].fd     = ifs->sd;
		pfd[ifnum].events = POLLIN;
		ifnum++;
	}

	while (1) {
		size_t i;

		timeout = tmo - time(NULL);
		if (timeout < 0)
			break;

		num = poll(pfd, ifnum, timeout * 1000);
		if (num < 0) {
			if (EINTR == errno)
				break;

			err(1, "Unrecoverable error");
		}

		if (num == 0)
			break;

		for (i = 0; num > 0 && i < ifnum; i++) {
			if (pfd[i].revents & POLLNVAL ||
			    pfd[i].revents & POLLHUP)
				return;

			if (pfd[i].revents & POLLIN) {
				handle_message(pfd[i].fd);
				num--;
			}
		}
	}
}

static void announce(int mod)
{
	struct ifsock *ifs;

	logit(LOG_INFO, "Sending SSDP NOTIFY new:%d ...", mod);

	LIST_FOREACH(ifs, &il, link) {
		size_t i;

		if (mod && !ifs->mod)
			continue;
		ifs->mod = 0;

//		send_search(ifs, "upnp:rootdevice");
		for (i = 0; supported_types[i]; i++) {
			/* UUID sent in SSDP_ST_ALL, first announce */
			if (!strcmp(supported_types[i], uuid))
				continue;

			send_message(ifs, supported_types[i], NULL);
		}
	}
}

static void lsb_init(void)
{
	const char *file = "/etc/lsb-release";
	char line[80];
	char *ptr;
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp) {
	fallback:
		logit(LOG_WARNING, "No %s found on system, using built-in server string.", file);
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		line[strlen(line) - 1] = 0;

		ptr = strstr(line, "DISTRIB_ID");
		if (ptr && (ptr = strchr(ptr, '='))) {
			if (os)
				free(os);
			os = strdup(++ptr);
		}

		ptr = strstr(line, "DISTRIB_RELEASE");
		if (ptr && (ptr = strchr(ptr, '='))) {
			if (ver)
				free(ver);
			ver = strdup(++ptr);
		}
	}
	fclose(fp);

	if (os && ver)
		snprintf(server_string, sizeof(server_string), "%s/%s UPnP/1.0 %s/%s",
			 os, ver, PACKAGE_NAME, PACKAGE_VERSION);
	else
		goto fallback;

	logit(LOG_DEBUG, "Server: %s", server_string);
}

/* https://en.wikipedia.org/wiki/Universally_unique_identifier */
static void uuidgen(void)
{
	const char *file = _PATH_VARDB PACKAGE_NAME ".cache";
	char buf[42];
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp) {
	generate:
		fp = fopen(file, "w");
		if (!fp)
			logit(LOG_WARNING, "Cannot create UUID cache, %s: %s", file, strerror(errno));

		srand(time(NULL));
		snprintf(buf, sizeof(buf), "uuid:%8.8x-%4.4x-%4.4x-%4.4x-%6.6x%6.6x",
			 rand() & 0xFFFFFFFF,
			 rand() & 0xFFFF,
			 (rand() & 0x0FFF) | 0x4000, /* M  4 MSB version => version 4 */
			 (rand() & 0x1FFF) | 0x8000, /* N: 3 MSB variant => variant 1 */
			 rand() & 0xFFFFFF, rand() & 0xFFFFFF);

		if (fp) {
			logit(LOG_DEBUG, "Creating new UUID cache file, %s", file);
			fprintf(fp, "%s\n", buf);
			fclose(fp);
		}
	} else {
		if (!fgets(buf, sizeof(buf), fp)) {
			fclose(fp);
			goto generate;
		}
		buf[strlen(buf) - 1] = 0;
		fclose(fp);
	}

	strcpy(uuid, buf);
	logit(LOG_DEBUG, "URN: %s", uuid);
}

static void exit_handler(int signo)
{
	(void)signo;
	running = 0;
}

static void signal_init(void)
{
	signal(SIGTERM, exit_handler);
	signal(SIGINT,  exit_handler);
	signal(SIGHUP,  exit_handler);
	signal(SIGQUIT, exit_handler);
	signal(SIGPIPE, SIG_IGN); /* get EPIPE instead */
}

static int usage(int code)
{
	printf("Usage: %s [-dhv] [-i SEC] [-r SEC] [-t TTL] [IFACE [IFACE ...]]\n"
	       "\n"
	       "    -d        Developer debug mode\n"
	       "    -h        This help text\n"
	       "    -i SEC    SSDP notify interval (30-900), default %d sec\n"
	       "    -n        Run in foreground, do not daemonize by default\n"
	       "    -r SEC    Interface refresh interval (5-1800), default %d sec\n"
	       "    -t TTL    TTL for multicast frames, default 2, according to the UDA\n"
	       "    -v        Show program version\n"
	       "\n"
	       "Bug report address : %s\n", PACKAGE_NAME, NOTIFY_INTERVAL, REFRESH_INTERVAL, PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
        printf("Project homepage   : %s\n", PACKAGE_URL);
#endif

	return code;
}

int main(int argc, char *argv[])
{
	time_t now, rtmo = 0, itmo = 0;
	int background = 1;
	int log_level = LOG_NOTICE;
	int log_opts = LOG_CONS | LOG_PID;
	int interval = NOTIFY_INTERVAL;
	int refresh = REFRESH_INTERVAL;
	int ttl = MC_TTL_DEFAULT;
	int i, c;

	while ((c = getopt(argc, argv, "dhi:nr:t:v")) != EOF) {
		switch (c) {
		case 'd':
			debug = 1;
			break;

		case 'h':
			return usage(0);

		case 'i':
			interval = atoi(optarg);
			if (interval < 30 || interval > 900)
				errx(1, "Invalid announcement interval (30-900).");
			break;

		case 'n':
			background = 0;
			break;

		case 'r':
			refresh = atoi(optarg);
			if (refresh < 5 || refresh > 1800)
				errx(1, "Invalid refresh interval (5-1800).");
			break;

		case 't':
			ttl = atoi(optarg);
			if (ttl < 1 || ttl > 255)
				errx(1, "Invalid TTL (1-255).");
			break;

		case 'v':
			puts(PACKAGE_VERSION);
			return 0;

		default:
			break;
		}
	}

	signal_init();

        if (debug) {
		log_level = LOG_DEBUG;
                log_opts |= LOG_PERROR;
	}

	if (background) {
		if (daemon(0, 0))
			err(1, "Failed daemonizing");
	}

        openlog(PACKAGE_NAME, log_opts, LOG_DAEMON);
        setlogmask(LOG_UPTO(log_level));

	uuidgen();
	lsb_init();
	web_init();
	pidfile(PACKAGE_NAME);

	while (running) {
		now = time(NULL);

		if (rtmo <= now) {
			if (ssdp_init(ttl, &argv[optind], argc - optind) > 0)
				announce(1);
			rtmo = now + refresh;
		}

		if (itmo <= now) {
			announce(0);
			itmo = now + interval;
		}

		wait_message(MIN(rtmo, itmo));
	}

	closelog();
	return close_socket();
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
