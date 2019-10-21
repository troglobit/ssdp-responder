/* SSDP scanner
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

#include <err.h>
#include "ssdp.h"
#include "queue.h"

#define hidecursor()          fputs ("\e[?25l", stdout)
#define showcursor()          fputs ("\e[?25h", stdout)

struct host {
	LIST_ENTRY(host) link;

	char *name;
	char *url;
};

LIST_HEAD(, host) hl = LIST_HEAD_INITIALIZER();

static int host(char *name, char *url)
{
	struct host *h;

	LIST_FOREACH(h, &hl, link) {
		if (strcmp(h->name, name))
			continue;
		if (strcmp(h->url, url))
			continue;

		return 1;
	}

	h = malloc(sizeof(*h));
	h->name = strdup(name);
	h->url  = strdup(url);

	LIST_INSERT_HEAD(&hl, h, link);

	return 0;
}

static void progress(void)
{
	size_t num = 4;
	const char *style = "\\-/|";
//	const char *style = ">v<^";
//	size_t num = 6;
//	const char *style = ".oOOo.";
	static unsigned int i = 0;

//	printf("%u %% %zd = %lu (%u / %zd = %lu)\n", i, num, i % num, i, num, i / num);

	putchar(style[i++ % num]);
	printf("\b");
	fflush(stdout);
}

static int ssdp_init(char *addr, short port)
{
       int sd;
       struct sockaddr sa;
       struct sockaddr_in *sin = (struct sockaddr_in *)&sa;

       sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
       if (sd < 0)
	       err(1, "Failed opening multicast socket");

       /* Allow reuse of local addresses. */
       ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEADDR);
#ifdef SO_REUSEPORT
       ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEPORT);
#endif

       memset(&sa, 0, sizeof(sa));
       sin->sin_family = AF_INET;
       sin->sin_addr.s_addr = inet_addr(addr);
       sin->sin_port = htons(port);

       if (bind(sd, &sa, sizeof(*sin)) < 0) {
               close(sd);
	       err(1, "Failed binding to %s:%d", addr, port);
       }

       return sd;
}

static void ssdp_scan(int sd)
{
	struct sockaddr_in sin;
	ssize_t num;
	char buf[200];
	int len;

	memset(buf, 0, sizeof(buf));
	len = snprintf(buf, sizeof(buf), "M-SEARCH * HTTP/1.1\r\n"
		       "Host: %s:%d\r\n"
		       "ST: %s\r\n"
		       "Man: \"ssdp:discover\"\r\n"
		       "MX: 3\r\n"
		       "\r\n",
		       MC_SSDP_GROUP, MC_SSDP_PORT,
		       "upnp:rootdevice");

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(MC_SSDP_PORT);
	sin.sin_addr.s_addr = inet_addr(MC_SSDP_GROUP);

	num = sendto(sd, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin));
	if (num < 0)
		warn("Failed sending SSDP M-SEARCH");
}

static char *find(char *buf, const char *search)
{
	size_t len;
	char *ptr;

	ptr = strcasestr(buf, search);
	if (!ptr)
		return NULL;

	ptr += strlen(search);
	while (*ptr && *ptr == ' ')
		ptr++;

	return ptr;
}

static char *trim(char *ptr)
{
	char *end = ptr;

	while (*end && *end != '\r' && *end != '\n')
		end++;
	*end = 0;

	return ptr;
}

static int xml(char *buf, char *tagn, char *val, size_t vlen)
{
	size_t len;
	char *ptr, *end;
	char tag[20];

	len = snprintf(tag, sizeof(tag), "<%s>", tagn);
//	printf("Looking for '%s' in: %s\n", tag, buf);
	ptr = strstr(buf, tag);
	if (!ptr)
		return 0;
	ptr += len;

	len = snprintf(tag, sizeof(tag), "</%s>", tagn);
	end = strstr(buf, tag);
	if (end)
		*end = 0;

	memset(val, 0, vlen);
	strncpy(val, ptr, vlen - 1);
//	printf(">> Found '%s': %s\n", tagn, val);

	return 1;
}

static void parse(FILE *fp, char **name, char **url)
{
	static char uri[80];
	static char nm[80];
	char buf[512];

	memset(uri, 0, sizeof(uri));
	memset(nm, 0, sizeof(nm));

	while (fgets(buf, sizeof(buf), fp)) {
//		printf("Checking XML for tags: '%s'\n", buf);
		if (!nm[0] && xml(buf, "friendlyName", nm, sizeof(nm)))
			*name = nm;
		if (!uri[0] && xml(buf, "presentationURL", uri, sizeof(uri)))
			*url = uri;

		if (*name && *url)
			break;
	}
}

extern FILE *uget(char *url);
static void printsrv(char *srv, char *loc)
{
	char *name = NULL, *url = NULL;
	char *copy;
	FILE *fp;

	/* Save copy in case of short/empty presentationURL */
	copy = strdup(loc);

	if (strncmp(loc, "http", 4))
		goto fallback;

	fp = uget(loc);
	if (!fp) {
	fallback:
		free(copy);
		printf("\r+ %-40s  %s\n", trim(srv), trim(loc));
		return;
	}

	parse(fp, &name, &url);
	fclose(fp);

	if (url && url[0] == '/') {
		char *ptr;

		copy = realloc(copy, strlen(copy) + strlen(url));
		if (!copy)
			return;

		ptr = strstr(copy, "://");
		if (ptr)
			ptr += 3;
		else
			ptr = copy;

		ptr = strchr(ptr, '/');
		if (ptr)
			strcpy(ptr, url);
		url = copy;
	}

	if (host(name, url))
		return;

	printf("\r+ %-40s  %s\n", name, url);
}

static void ssdp_read(int sd)
{
	ssize_t len;
	char *loc;
	char *srv;
	char *ptr;
	char buf[512];

	memset(buf, 0, sizeof(buf));
	len = recv(sd, buf, sizeof(buf) - 1, 0);

	if (strstr(buf, "M-SEARCH *"))
		return;

	loc = find(buf, "Location:");
	srv = find(buf, "Server:");

	if (!loc || !srv)
		return;

	trim(loc);
	trim(srv);

	printsrv(srv, loc);
}

static void bye(int signo)
{
	showcursor();
	exit(0);
}

int main(void)
{
	struct pollfd pfd[2];

	signal(SIGINT, bye);

	hidecursor();
	progress();

	/* Listen to both 239.255.255.250 and INADDR_ANY */
	pfd[0].fd = ssdp_init(MC_SSDP_GROUP, MC_SSDP_PORT);
	pfd[1].fd = ssdp_init("0.0.0.0", MC_SSDP_PORT);

	pfd[0].events = POLLIN;
	pfd[1].events = POLLIN;

	/* Initial scan */
	ssdp_scan(pfd[0].fd);

	while (1) {
		int num;

		num = poll(pfd, NELEMS(pfd), 100);
		if (num < 0)
			continue;

		if (num == 0) {
			progress();
			ssdp_scan(pfd[0].fd);
			continue;
		}

		for (size_t i = 0; i < NELEMS(pfd); i++) {
			progress();
			if (pfd[i].revents & POLLIN)
				ssdp_read(pfd[i].fd);
		}
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
