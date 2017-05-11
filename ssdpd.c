/* SSDP responder
 *
 * Copyright (c) 2017  Joachim Nilsson <troglobit@gmail.com>
 * Copyright (c) 2017  Tobias Waldekranz <tobias@waldekranz.com>
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

#include <config.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
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

#define NOTIFY_INTERVAL      30
#define MAX_NUM_IFACES       100
#define MAX_PKT_SIZE         512
#define MC_SSDP_GROUP        "239.255.255.250"

typedef struct {
	int   sd;
	char *ifname;
	void (*cb)(int);
} ifsock_t;

int      running = 1;
size_t   ifnum = 0;
ifsock_t iflist[MAX_NUM_IFACES];

char uuid[42];
in_addr_t graal;

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

	val = 1;
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

static void compose_addr(struct sockaddr_in *sin, char *group)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family      = AF_INET;
	sin->sin_addr.s_addr = inet_addr(group);
}

static void send_message(int sd, struct sockaddr *sa, socklen_t salen)
{
	size_t i;
	time_t now;
	char *http;
	char date[42];
	char host[NI_MAXHOST] = "1.2.3.4";
	unsigned char buf[MAX_PKT_SIZE];
	struct udphdr *uh;
	struct sockaddr dest;
	struct sockaddr_in *sin;

	memset(buf, 0, sizeof(buf));
	uh = (struct udphdr *)buf;
	uh->uh_sport = htons(1900);
	if (sa)
		uh->uh_dport = ((struct sockaddr_in *)sa)->sin_port;
	else
		uh->uh_dport = htons(1900);

	getifaddr(sd, host, sizeof(host));

	now = time(NULL);
	snprintf(date, sizeof(date), "%s", ctime(&now));
	date[strlen(date) - 1] = 0;

	http = (char *)(buf + sizeof(*uh));
	if (sa)
		snprintf(http, sizeof(buf) - sizeof(*uh), "HTTP/1.1 200 OK\r\n"
			 "Server: WeOS 5.0, UPnP/1.1, corazon/1.0\r\n"
			 "Date: %s\r\n"
			 "Location: http://%s:1900/description.xml\r\n"
			 "ST: upnp:rootdevice\r\n"
			 "EXT: \r\n"
			 "USN: uuid:%s\r\n"
			 "Cache-Control: max-age=3600\r\n"
			 "\r\n", date, host, uuid);
	else
		snprintf(http, sizeof(buf) - sizeof(*uh), "NOTIFY * HTTP/1.1\r\n"
			 "Host: 239.255.255.250:1900\r\n"
			 "Server: WeOS 5.0, UPnP/1.1, corazon/1.0\r\n"
			 "Cache-Control: max-age=3600\r\n"
			 "Location: http://%s:1900/description.xml\r\n"
			 "NT: uuid:%s\r\n"
			 "NTS: ssdp:alive\r\n"
			 "USN: uuid:%s\r\n"
			 "\r\n", host, uuid, uuid);

	uh->uh_ulen = htons(strlen(http) + sizeof(*uh));
	uh->uh_sum = in_cksum((unsigned short *)uh, sizeof(*uh));

	if (!sa) {
		compose_addr((struct sockaddr_in *)&dest, MC_SSDP_GROUP);
		sa = &dest;
		salen = sizeof(dest);
	}

	for (i = 0; i < ifnum; i++) {
		ssize_t num;

		num = sendto(sd, buf, sizeof(buf), 0, sa, salen);
		if (num < 0)
			warn("Failed sending SSDP message");
	}
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
		if (uh->uh_dport != htons(1900))
			return;

		http = (char *)(uh + sizeof(struct udphdr));
		http = (char *)(buf + (ip->ip_hl << 2) + sizeof(struct udphdr));
		if (strstr(http, "M-SEARCH *"))
			send_message(sd, &sa, salen);
	}
}

static void wait_message(uint8_t interval)
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

static void announce(void)
{
	size_t i;

	for (i = 0; i < ifnum; i++) {
		if (!iflist[i].ifname)
			continue;

		send_message(iflist[i].sd, NULL, 0);
	}
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
	printf("\nUsage: %s [-i SEC] IFACE [IFACE ...]\n"
	       "\n"
	       "    -h        This help text\n"
	       "    -i SEC    Announce interval, default %d sec\n"
	       "\n"
	       "Bug report address: %-40s\n\n", PACKAGE_NAME, NOTIFY_INTERVAL, PACKAGE_BUGREPORT);

	return code;
}

int main(int argc, char *argv[])
{
	int i, c;
	uint8_t interval = NOTIFY_INTERVAL;

	while ((c = getopt(argc, argv, "hi:")) != EOF) {
		switch (c) {
		case 'h':
			return usage(0);

		case 'i':
			interval = (uint8_t)atoi(optarg);
			if (interval < 4 || interval > 180)
				errx(1, "Invalid announcement interval [1,60]");
			break;

		default:
			break;
		}
	}

	if (optind >= argc) {
		warnx("Not enough arguments");
		return usage(1);
	}

	signal_init();

	snprintf(uuid, sizeof(uuid), "%8x-%8x-%8x-%8x", rand(), rand(), rand(), rand());

	for (i = optind; i < argc; i++)
		open_ssdp_socket(argv[i]);

	while (running) {
		announce();
		wait_message(interval);
	}

	return close_socket();
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
