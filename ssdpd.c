/* SSDP responder
 *
 * Copyright (c) 2017  Joachim Nilsson <troglobit@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <config.h>
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
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "ssdp.h"
#include "lssdp.h"

typedef struct {
	int   sd;
	char *ifname;
	void (*cb)(int);
} ifsock_t;

char uuid[42];

static char *supported_types[] = {
	SSDP_ST_ALL,
	"upnp:rootdevice",
//	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	uuid,
	NULL
};

lssdp_ctx ctx = {
	.debug = true,           // debug
	.port = 1900,
	.neighbor_timeout = 15000,  // 15 seconds
	.header = {
		.search_target       = "urn:schemas-upnp-org:device:InternetGatewayDevice:1", //"ST_P2P",
		.unique_service_name = "f835dd000001",
		.sm_id               = "700000123",
		.device_type         = "DEV_TYPE",
		.location.suffix     = ":1900/description.xml"
	},

	// callback
	.neighbor_list_changed_callback     = NULL,
	.network_interface_changed_callback = NULL,
};


int      debug = 0;
int      running = 1;
size_t   ifnum = 0;
ifsock_t iflist[MAX_NUM_IFACES];

char host[NI_MAXHOST] = "1.2.3.4";
char hostname[64];
char *os = NULL, *ver = NULL;
char server_string[64] = "POSIX UPnP/1.0 " PACKAGE_NAME "/" PACKAGE_VERSION;

in_addr_t graal;

void open_web_socket(char *ifname);
unsigned short in_cksum(unsigned short *addr, int len);
static void ssdp_recv(int sd);

void register_socket(int sd, char *ifname, void (*cb)(int sd))
{
	iflist[ifnum].sd = sd;
	iflist[ifnum].ifname = ifname;
	iflist[ifnum].cb = cb;
	ifnum++;
}

void open_ssdp_socket(char *ifname)
{
	char loop;
	int sd, val, rc;
	struct ifreq ifr;
	struct ip_mreqn mreq;

	sd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
	if (sd < 0)
		err(1, "Cannot open socket");

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		if (ENODEV == errno) {
			warnx("Not a valid interface, %s, skipping ...", ifname);
			close(sd);
			return;
		}

		err(1, "Cannot bind socket to interface %s", ifname);
	}

	memset(&mreq, 0, sizeof(mreq));
	graal = inet_addr(MC_SSDP_GROUP);
	mreq.imr_multiaddr.s_addr = graal;
	mreq.imr_ifindex = if_nametoindex(ifname);
        if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)))
		err(1, "Failed joining group %s", MC_SSDP_GROUP);

	val = 2;		/* Default 2, but should be configurable */
	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &val, sizeof(val));
	if (rc < 0)
		err(1, "Cannot set TTL");

	loop = 0;
	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	if (rc < 0)
		err(1, "Cannot disable MC loop");

	register_socket(sd, ifname, ssdp_recv);
}

static int close_socket(void)
{
	size_t i;
	int ret = 0;

	for (i = 0; i < ifnum; i++)
		ret |= close(iflist[i].sd);

	return ret;
}

static void getifaddr(int sd, char *host, size_t len)
{
	size_t i;
	char *ifname = NULL;;
	struct ifaddrs *ifaddrs, *ifa;

	if (getifaddrs(&ifaddrs) < 0)
		err(1, "Failed getifaddrs()");

	for (i = 0; i < ifnum; i++) {
		if (iflist[i].sd != sd)
			continue;

		ifname = iflist[i].ifname;
	}

	if (!ifname)
		errx(1, "Cannot find a matching interface for socket %d", sd);

	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		int s;

		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;

		if (strcmp(ifa->ifa_name, ifname))
			continue;

		s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
				host, len, NULL, 0, NI_NUMERICHOST);
		if (s)
			errx(1, "Failed getnameinfo(): %s", gai_strerror(s));
		break;
	}
	freeifaddrs(ifaddrs);
}

static void compose_addr(struct sockaddr_in *sin, char *group, int port)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family      = AF_INET;
	sin->sin_port        = htons(MC_SSDP_PORT);
	sin->sin_addr.s_addr = inet_addr(group);
}

static void compose_response(char *type, char *buf, size_t len)
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
		strncpy(usn, uuid, sizeof(usn));

	snprintf(buf, len, "HTTP/1.1 200 OK\r\n"
		 "CACHE-CONTROL:%s\r\n"
//		 "Date: %s\r\n"
		 "DATE:\r\n"
		 "EXT:\r\n"
		 "LOCATION:%s:%d\r\n" ///%s\r\n"
		 "SERVER:%s\r\n"
		 "ST: %s\r\n"
		 "USN: %s\r\n"
		 "\r\n",
		 CACHING,
//		 date,
		 host, LOCATION_PORT, //LOCATION_DESC,
		 server_string,
		 type,
		 usn);
}

static void compose_search(char *type, char *buf, size_t len)
{
	snprintf(buf, len, "M-SEARCH * HTTP/1.1\r\n"
		 "HOST:%s:%d\r\n"
		 "MAN:\"ssdp:discover\"\r\n"
		 "MX:1\r\n"
		 "ST:%s\r\n"
		 "USER-AGENT:%s\r\n"
		 "\r\n",
		 MC_SSDP_GROUP, MC_SSDP_PORT,
		 type,
		 server_string);
}

static void compose_notify(char *type, char *buf, size_t len)
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
		strncpy(usn, uuid, sizeof(usn));
	}

	snprintf(buf, len, "NOTIFY * HTTP/1.1\r\n"
		 "HOST:%s:%d\r\n"
		 "CACHE-CONTROL:%s\r\n"
		 "LOCATION:%s:%d\r\n" ///%s\r\n"
		 "SERVER:%s\r\n"
		 "NT:%s\r\n"
		 "NTS:ssdp:alive\r\n"
		 "USN:%s\r\n"
		 "\r\n", MC_SSDP_GROUP, MC_SSDP_PORT,
		 CACHING,
		 host, LOCATION_PORT, //LOCATION_DESC,
		 server_string,
		 type,
		 usn);
}

size_t pktlen(unsigned char *buf)
{
	size_t hdr = sizeof(struct udphdr);

	return strlen((char *)buf + hdr) + hdr;
}

static void send_search(int sd, char *type)
{
	size_t i, len, note = 0;
	ssize_t num;
	char *http;
	unsigned char buf[MAX_PKT_SIZE];
	struct udphdr *uh;
	struct sockaddr dest;
	struct sockaddr_in *sin;

	memset(buf, 0, sizeof(buf));
	uh = (struct udphdr *)buf;
	uh->uh_sport = htons(MC_SSDP_PORT);
	uh->uh_dport = htons(MC_SSDP_PORT);

	getifaddr(sd, host, sizeof(host));
	gethostname(hostname, sizeof(hostname));

	http = (char *)(buf + sizeof(*uh));
	len = sizeof(buf) - sizeof(*uh);
	compose_search(type, http, len);

	uh->uh_ulen = htons(strlen(http) + sizeof(*uh));
	uh->uh_sum = in_cksum((unsigned short *)uh, sizeof(*uh));

	compose_addr((struct sockaddr_in *)&dest, MC_SSDP_GROUP, MC_SSDP_PORT);

	logit(LOG_DEBUG, "Sending M-SEARCH ...");
	num = sendto(sd, buf, pktlen(buf), 0, &dest, sizeof(struct sockaddr_in));
	if (num < 0)
		logit(LOG_WARNING, "Failed sending SSDP M-SEARCH");
}

static void send_message(int sd, char *type, struct sockaddr *sa, socklen_t salen)
{
	size_t i, len, note = 0;
	ssize_t num;
	char *http;
	unsigned char buf[MAX_PKT_SIZE];
	struct udphdr *uh;
	struct sockaddr dest;
	struct sockaddr_in *sin;

	memset(buf, 0, sizeof(buf));
	uh = (struct udphdr *)buf;
	uh->uh_sport = htons(MC_SSDP_PORT);
	if (sa)
		uh->uh_dport = ((struct sockaddr_in *)sa)->sin_port;
	else
		uh->uh_dport = htons(MC_SSDP_PORT);

	getifaddr(sd, host, sizeof(host));
	gethostname(hostname, sizeof(hostname));

	if (!strcmp(type, SSDP_ST_ALL))
		type = NULL;

	http = (char *)(buf + sizeof(*uh));
	len = sizeof(buf) - sizeof(*uh);
	if (sa)
		compose_response(type, http, len);
	else
		compose_notify(type, http, len);

	uh->uh_ulen = htons(strlen(http) + sizeof(*uh));
	uh->uh_sum = in_cksum((unsigned short *)uh, sizeof(*uh));

	if (!sa) {
		note = 1;
		compose_addr((struct sockaddr_in *)&dest, MC_SSDP_GROUP, MC_SSDP_PORT);
		sa = &dest;
		salen = sizeof(dest);
	}

	logit(LOG_DEBUG, "Sending %s ...", !note ? "reply" : "notify");
	num = sendto(sd, buf, pktlen(buf), 0, sa, salen);
	if (num < 0)
		logit(LOG_WARNING, "Failed sending SSDP %s, type: %s", !note ? "reply" : "notify", type);
}

static void ssdp_recv(int sd)
{
	ssize_t len;
	struct sockaddr sa;
	socklen_t salen;
	unsigned char buf[MAX_PKT_SIZE];

	memset(buf, 0, sizeof(buf));
	len = recvfrom(sd, buf, sizeof(buf), MSG_DONTWAIT, &sa, &salen);
	if (len > 0) {
		struct ip *ip;
		struct udphdr *uh;
		char *http;

		buf[len] = 0;
		ip = (struct ip *)buf;
		if (ip->ip_dst.s_addr != graal)
			return;

		uh = (struct udphdr *)(buf + (ip->ip_hl << 2));
		if (uh->uh_dport != htons(MC_SSDP_PORT))
			return;

		if (sa.sa_family != AF_INET)
			return;

		http = (char *)(uh + sizeof(struct udphdr));
		http = (char *)(buf + (ip->ip_hl << 2) + sizeof(struct udphdr));
		if (strstr(http, "M-SEARCH *")) {
			size_t i;
			char *ptr, *type;
			struct sockaddr_in *sin = (struct sockaddr_in *)&sa;

			/* Set source port as destination in our reply */
			sin->sin_port = uh->uh_sport;

			type = strcasestr(http, "\r\nST:");
			if (!type) {
				logit(LOG_DEBUG, "No Search Type (ST:) found in M-SEARCH *, assuming " SSDP_ST_ALL);
				type = SSDP_ST_ALL;
				send_message(sd, type, &sa, salen);
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
					send_message(sd, type, &sa, salen);
					return;
				}
			}

			logit(LOG_DEBUG, "M-SEARCH * for unsupported ST: %s from %s", type,
			      inet_ntoa(sin->sin_addr));
		}
	}
}

static void wait_message(lssdp_ctx *ctx, uint8_t interval)
{
	size_t i;
	int num = 1;
	time_t end = time(NULL) + interval;
	struct pollfd pfd[MAX_NUM_IFACES];

	for (i = 0; i < ifnum; i++) {
		pfd[i].fd = iflist[i].sd;
		pfd[i].events = POLLIN | POLLHUP;
	}

again:
	while (1) {
		num = poll(pfd, ifnum, (end - time(NULL)) * 1000);
		if (num < 0) {
			if (EINTR == errno)
				break;

			err(1, "Unrecoverable error");
		}

		if (num == 0)
			break;

		for (i = 0; num > 0 && i < ifnum; i++) {
			if (pfd[i].revents & POLLIN) {
				iflist[i].cb(iflist[i].sd);
				num--;
			}
		}
	}
}

static void announce(lssdp_ctx *ctx)
{
#if 0
	size_t i;

	for (i = 0; i < ifnum; i++) {
		size_t j;

		if (!iflist[i].ifname)
			continue;

		send_search(iflist[i].sd, "upnp:rootdevice");
		for (j = 0; supported_types[j]; j++) {
			/* UUID sent in SSDP_ST_ALL, first announce */
			if (!strcmp(supported_types[j], uuid))
				continue;

			send_message(iflist[i].sd, supported_types[j], NULL, 0);
		}
	}
#else
	lssdp_send_msearch(ctx);             // 2. send M-SEARCH
	lssdp_send_notify(ctx);              // 3. send NOTIFY
	lssdp_neighbor_check_timeout(ctx);   // 4. check neighbor timeout
#endif
}

static void lsb_init(void)
{
	FILE *fp;
	char *ptr;
	char line[80];
	const char *file = "/etc/lsb-release";

	fp = fopen(file, "r");
	if (!fp) {
	fallback:
		logit(LOG_WARNING, "No %s found on system, using built-in server string.", file);
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		line[strlen(line) - 1] = 0;

		ptr = strstr(line, "DISTRIB_ID");
		if (ptr && (ptr = strchr(ptr, '=')))
			os = strdup(++ptr);

		ptr = strstr(line, "DISTRIB_RELEASE");
		if (ptr && (ptr = strchr(ptr, '=')))
			ver = strdup(++ptr);
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
	FILE *fp;
	char buf[42];
	const char *file = _PATH_VARDB PACKAGE_NAME ".cache";

	fp = fopen(file, "r");
	if (!fp) {
		fp = fopen(file, "w");
		if (!fp)
			logit(LOG_WARNING, "Cannot create UUID cache, %s: %s", file, strerror(errno));

	generate:
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

void log_callback(const char *file, const char *tag, int level, int line, const char *func, const char *message)
{
    if (level == LSSDP_LOG_INFO)
	    level = LOG_INFO;
    else if (level == LSSDP_LOG_WARN)
	    level = LOG_WARNING;
    else if (level == LSSDP_LOG_ERROR)
	    level = LOG_ERR;
    else
	    level = LOG_DEBUG;

    logit(level, "%s: %s", tag, message);
}

static void exit_handler(int signo)
{
	running = 0;
}

static void signal_init(void)
{
	signal(SIGTERM, exit_handler);
	signal(SIGINT,  exit_handler);
	signal(SIGHUP,  exit_handler);
	signal(SIGQUIT, exit_handler);
}

static int usage(int code)
{
	printf("Usage: %s [-dhv] [-i SEC] IFACE [IFACE ...]\n"
	       "\n"
	       "    -d        Developer debug mode\n"
	       "    -h        This help text\n"
	       "    -i SEC    Announce interval, default %d sec\n"
	       "    -v        Show program version\n"
	       "\n"
	       "Bug report address: %-40s\n", PACKAGE_NAME, NOTIFY_INTERVAL, PACKAGE_BUGREPORT);

	return code;
}

static void do_recv(int sd)
{
	if (ctx.sock == sd)
		lssdp_socket_read(&ctx);
}


static int rebind_socket(lssdp_ctx *ctx)
{
	int pos = -1;
	size_t i;

	for (i = 0; i < ctx->interface_num; i++) {
		printf("%zu. %-6s: %s\n",
		       i + 1,
		       ctx->interface[i].name,
		       ctx->interface[i].ip
			);
	}

	for (i = 0; i < ifnum; i++) {
		if (iflist[i].sd != ctx->sock)
			continue;

		pos = (int)i;
		break;
	}

	if (lssdp_socket_create(ctx)) {
		logit(LOG_ERR, "SSDP create socket failed");
		return -1;
	}

	if (-1 == pos)
		register_socket(ctx->sock, NULL, do_recv);
	else
		iflist[pos].sd = ctx->sock;

	return 0;
}

int main(int argc, char *argv[])
{
	int i, c;
	int log_level = LOG_NOTICE;
	int log_opts = LOG_CONS | LOG_PID;
	uint8_t interval = NOTIFY_INTERVAL;

	while ((c = getopt(argc, argv, "dhi:v")) != EOF) {
		switch (c) {
		case 'd':
			debug = 1;
			break;

		case 'h':
			return usage(0);

		case 'i':
			interval = (uint8_t)atoi(optarg);
			if (interval < 4 || interval > 180)
				errx(1, "Invalid announcement interval [1,60]");
			break;

		case 'v':
			puts(PACKAGE_VERSION);
			return 0;

		default:
			break;
		}
	}

	if (optind >= argc) {
		warnx("Not enough arguments");
		return usage(1);
	}

	signal_init();

        if (debug) {
		log_level = LOG_DEBUG;
                log_opts |= LOG_PERROR;
	}

        openlog(PACKAGE_NAME, log_opts, LOG_DAEMON);
        setlogmask(LOG_UPTO(log_level));

	/*
	 * get network interface at first time,
	 * network_interface_changed_callback will be invoke SSDP socket
	 * will be created in callback function
	 */
	ctx.network_interface_changed_callback = rebind_socket;
	lssdp_network_interface_update(&ctx);
	lssdp_set_log_callback(log_callback);

	uuidgen();
	lsb_init();

	strncpy(ctx.header.unique_service_name, uuid, sizeof(ctx.header.unique_service_name));
	strncpy(ctx.header.server_string, server_string, sizeof(ctx.header.server_string));
//	for (i = optind; i < argc; i++)
//		open_ssdp_socket(argv[i]);
	open_web_socket(NULL);

//	announce(&ctx);
	while (running) {
		announce(&ctx);
		wait_message(&ctx, interval);
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
