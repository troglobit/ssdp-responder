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

#include <sys/utsname.h>	/* uname() for !__linux__ */
#include "ssdp.h"

char  server_string[64] = "POSIX UPnP/1.0 " PACKAGE_NAME "/" PACKAGE_VERSION;
char  hostname[64];
char *ver = NULL;
char *os  = NULL;
char  uuid[42];

static char *supported_types[] = {
	SSDP_ST_ALL,
	"upnp:rootdevice",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	uuid,
	NULL
};

volatile sig_atomic_t running = 1;

extern void web_init(void);


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

static void send_message(struct ifsock *ifs, char *type, struct sockaddr *sa, socklen_t salen)
{
	struct sockaddr_in dest;
	char host[NI_MAXHOST];
	char buf[MAX_PKT_SIZE];
	size_t note = 0;
	ssize_t num;
	int s;

	if (ifs->addr.sin_addr.s_addr == htonl(INADDR_ANY))
		return;

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
	if (sa)
		compose_response(type, host, buf, sizeof(buf));
	else
		compose_notify(type, host, buf, sizeof(buf));

	if (!sa) {
		note = 1;
		compose_addr(&dest, MC_SSDP_GROUP, MC_SSDP_PORT);
		sa = (struct sockaddr *)&dest;
		salen = sizeof(struct sockaddr_in);
	}

	logit(LOG_DEBUG, "Sending %s from %s ...", !note ? "reply" : "notify", host);
	num = sendto(ifs->sd, buf, strlen(buf), 0, sa, salen);
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

			ifs = ssdp_find(&sa);
			if (!ifs) {
				logit(LOG_DEBUG, "No matching socket for client %s", inet_ntoa(sin->sin_addr));
				return;
			}
			logit(LOG_DEBUG, "Matching socket for client %s", inet_ntoa(sin->sin_addr));

			type = strcasestr(buf, "\r\nST:");
			if (!type) {
				logit(LOG_DEBUG, "No Search Type (ST:) found in M-SEARCH *, assuming " SSDP_ST_ALL);
				type = SSDP_ST_ALL;
				send_message(ifs, type, &sa, salen);
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
					send_message(ifs, type, &sa, salen);
					return;
				}
			}

			logit(LOG_DEBUG, "M-SEARCH * for unsupported ST: %s from %s", type,
			      inet_ntoa(sin->sin_addr));
		}
	}
}

static void wait_message(time_t tmo)
{
	while (1) {
		int timeout;

		timeout = tmo - time(NULL);
		if (timeout < 0)
			break;

		if (ssdp_poll(timeout * 1000) == -1) {
			if (errno == EINTR)
				break;

			err(1, "Unrecoverable error");
		}
	}
}

static void announce(struct ifsock *ifs, int mod)
{
	if (mod && !ifs->mod)
		return;
	ifs->mod = 0;

	for (size_t i = 0; supported_types[i]; i++) {
		/* UUID sent in SSDP_ST_ALL, first announce */
		if (!strcmp(supported_types[i], uuid))
			continue;

		send_message(ifs, supported_types[i], NULL, 0);
	}
}

static char *strip_quotes(char *str)
{
	char *ptr;

	if (!str)
		return NULL;
	while (*str && isspace(*str))
		str++;
	if (*str == '"')
		str++;

	ptr = str;
	while (*ptr && !isspace(*ptr) && *ptr != '"')
		ptr++;
	*ptr = 0;

	return str;
}

static int os_init(void)
{
	const char *file = "/etc/os-release";
	char line[80];
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp)
		return 1;

	while (fgets(line, sizeof(line), fp)) {
		char *ptr;

		line[strlen(line) - 1] = 0;

		if (!strncmp(line, "NAME", 4) && (ptr = strchr(line, '='))) {
			logit(LOG_DEBUG, "Found NAME:%s", ptr + 1);
			if (os)
				free(os);
			os = strdup(strip_quotes(++ptr));
		}

		if (!strncmp(line, "VERSION_ID", 10) && (ptr = strchr(line, '='))) {
			logit(LOG_DEBUG, "Found VERSION_ID:%s", ptr + 1);
			if (ver)
				free(ver);
			ver = strdup(strip_quotes(++ptr));
		}
	}

	logit(LOG_DEBUG, "Found os:%s ver:%s", os, ver);
	fclose(fp);

	return 0;
}

static void lsb_init(void)
{
	const char *file = "/etc/lsb-release";
	int severity = LOG_INFO;
	char line[80];
	char *ptr;
	FILE *fp;

	if (!os_init())
		goto fallback;

	fp = fopen(file, "r");
	if (!fp) {
#ifndef __linux__
		struct utsname uts;

		if (!uname(&uts)) {
			os  = strdup(uts.sysname);
			ver = strdup(uts.release);
		}
#endif
		goto fallback;
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

fallback:
	if (os && ver)
		snprintf(server_string, sizeof(server_string), "%s/%s UPnP/1.0 %s/%s",
			 os, ver, PACKAGE_NAME, PACKAGE_VERSION);
	else {
		logit(LOG_WARNING, "No %s found on system, using built-in server string.", file);
		severity = LOG_WARNING;
	}

	logit(severity, "Server: %s", server_string);
}

static void lsb_exit(void)
{
	if (os)
		free(os);
	if (ver)
		free(ver);
}

/*
 * _CACHEDIR is the configurable fallback.  We only read that, if it
 * exists, otherwise we use the system _PATH_VARDB, which works on all
 * *BSD and GLIBC based Linux systems.  Some Linux systms don't have the
 * correct FHS /var/lib/misc for that define, so we check for that too.
 */
static FILE *fopen_cache(char *mode, char *fn, size_t len)
{
	snprintf(fn, len, _CACHEDIR "/" PACKAGE_NAME ".cache");
	if (access(fn, R_OK | W_OK)) {
		if (!access(_PATH_VARDB, W_OK))
			snprintf(fn, len, "%s/" PACKAGE_NAME ".cache", _PATH_VARDB);
	}

	return fopen(fn, mode);
}

/* https://en.wikipedia.org/wiki/Universally_unique_identifier */
static void uuidgen(void)
{
	char file[256];
	char buf[42];
	FILE *fp;

	fp = fopen_cache("r", file, sizeof(file));
	if (!fp) {
	generate:
		fp = fopen_cache("w", file, sizeof(file));
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
	printf("Usage: %s [-hnsv] [-i SEC] [-l LEVEL] [-r SEC] [-t TTL] [IFACE [IFACE ...]]\n"
	       "\n"
	       "    -h        This help text\n"
	       "    -i SEC    SSDP notify interval (30-900), default %d sec\n"
	       "    -l LVL    Set log level: none, err, notice (default), info, debug\n"
	       "    -n        Run in foreground, do not daemonize by default\n"
	       "    -r SEC    Interface refresh interval (5-1800), default %d sec\n"
	       "    -s        Use syslog, default unless running in foreground, -n\n"
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
	int interval = NOTIFY_INTERVAL;
	int refresh = REFRESH_INTERVAL;
	int ttl = MC_TTL_DEFAULT;
	int do_syslog = 1;
	int c;

	while ((c = getopt(argc, argv, "hi:l:nr:st:v")) != EOF) {
		switch (c) {
		case 'h':
			return usage(0);

		case 'i':
			interval = atoi(optarg);
			if (interval < 30 || interval > 900)
				errx(1, "Invalid announcement interval (30-900).");
			break;

		case 'l':
			log_level = log_str2lvl(optarg);
			if (-1 == log_level)
				return usage(1);
			break;

		case 'n':
			background = 0;
			do_syslog--;
			break;

		case 'r':
			refresh = atoi(optarg);
			if (refresh < 5 || refresh > 1800)
				errx(1, "Invalid refresh interval (5-1800).");
			break;

		case 's':
			do_syslog++;
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

	if (background) {
		if (daemon(0, 0))
			err(1, "Failed daemonizing");
	}

	log_init(do_syslog);
	uuidgen();
	lsb_init();
	web_init();
	pidfile(PACKAGE_NAME);

	while (running) {
		now = time(NULL);

		if (rtmo <= now) {
			if (ssdp_init(ttl, 1, &argv[optind], argc - optind, ssdp_recv) > 0) {
				logit(LOG_INFO, "Sending SSDP NOTIFY on new interfaces ...");
				ssdp_foreach(announce, 1);
			}
			rtmo = now + refresh;
		}

		if (itmo <= now) {
			logit(LOG_INFO, "Sending SSDP NOTIFY ...");
			ssdp_foreach(announce, 0);
			itmo = now + interval;
		}

		wait_message(MIN(rtmo, itmo));
	}

	lsb_exit();
	log_exit();

	return ssdp_exit();
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
