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

static int ssdp_init(void)
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
       sin->sin_addr.s_addr = inet_addr(MC_SSDP_GROUP);
       sin->sin_port = htons(MC_SSDP_PORT);

       if (bind(sd, &sa, sizeof(*sin)) < 0) {
               close(sd);
	       err(1, "Failed binding to %s:%d", MC_SSDP_GROUP, MC_SSDP_PORT);
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

static void ssdp_read(int sd)
{
	ssize_t len;
	char *loc;
	char *srv;
	char *ptr;
	char buf[256];

	memset(buf, 0, sizeof(buf));
	len = recv(sd, buf, sizeof(buf) - 1, MSG_DONTWAIT);

	if (strstr(buf, "M-SEARCH *")) {
	cont:
		putchar('.');
		return;
	}

	loc = find(buf, "Location:");
	srv = find(buf, "Server:");

	if (!loc || !srv)
		goto cont;

	printf("\r+ %-30s  %s\n", trim(srv), trim(loc));
}

int main(void)
{
	struct pollfd pfd;

	pfd.fd = ssdp_init();
	pfd.events = POLLIN;

	/* Initial scan */
	ssdp_scan(pfd.fd);

	while (1) {
		int num;

		num = poll(&pfd, 1, 3000);
		if (num == 0)
			ssdp_scan(pfd.fd);
		else if (num > 0)
			ssdp_read(pfd.fd);
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
