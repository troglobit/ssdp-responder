/* Really stupid get-file-over-http program/function
 *
 * Copyright (c) 2020  Joachim Nilsson <troglobit@gmail.com>
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
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

static void split(char *url, char **server, uint16_t *port, char **location)
{
	char *ptr, *pptr;

	if (!url)
		return;

	ptr = strstr(url, "://");
	if (!ptr)
		ptr = url;
	else
		ptr += 3;
	*server = ptr;

	ptr = strchr(ptr, ':');
	if (ptr) {
		*ptr++ = 0;
		pptr = ptr;
	} else {
		ptr = *server;
		if (!strncmp(url, "http://", 7))
			pptr = "80";
		else
			pptr = "443";
	}

	ptr = strchr(ptr, '/');
	if (!ptr)
		return;

	*ptr++ = 0;
	*location = ptr;

	if (pptr)
		*port = atoi(pptr);
}

static int nslookup(char *server, uint16_t port, struct addrinfo **result)
{
	struct addrinfo hints;
	char service[10];
	int rc;

	snprintf(service, sizeof(service), "%d", port);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family   = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags    = 0;
	hints.ai_protocol = 0;

	rc = getaddrinfo(server, service, &hints, result);
	if (rc) {
		warnx("Failed looking up %s:%s: %s", server, service, gai_strerror(rc));
		return -1;
	}

	return 0;
}

static int get(int sd, struct addrinfo *ai, char *host, uint16_t port, char *location)
{
	struct pollfd pfd;
	ssize_t num;
	size_t len;
	char buf[256];

	len = snprintf(buf, sizeof(buf), "GET /%s HTTP/1.1\r\n"
		       "Host: %s:%d\r\n"
		       "Cache-Control: no-cache\r\n"
		       "Connection: close\r\n"
		       "Pragma: no-cache\r\n"
		       "Accept: text/xml, application/xml\r\n"
		       "User-Agent: ssdp-scan/1.0 UPnP/1.0\r\n"
		       "\r\n",
		       location, host, port);

	num = sendto(sd, buf, len, 0, ai->ai_addr, ai->ai_addrlen);
	if (num < 0) {
		warn("Failed sending HTTP GET /%s to %s:%d", location, host, port);
		close(sd);
		return -1;
	}

	pfd.fd = sd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 1000) < 0) {
		warn("Server %s: %s", host, strerror(errno));
		freeaddrinfo(ai);
		close(sd);
		return -1;
	}

	return sd;
}

static int hello(struct addrinfo *ai, uint16_t port, char *location)
{
	struct sockaddr_in *sin;
	struct addrinfo *rp;
	char host[20];
	int sd;

	for (rp = ai; rp != NULL; rp = rp->ai_next) {
		struct timeval timeout = { 0, 200000 };

		sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sd == -1)
			continue;

		/* Attempt to adjust recv timeout */
		if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
			warn("Failed setting recv() timeout");

		if (connect(sd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;	/* Success */

		sin = (struct sockaddr_in *)rp->ai_addr;
		inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
		warn("Failed connecting to %s:%d", host, ntohs(sin->sin_port));

		close(sd);
	}

	if (rp == NULL)
		return -1;

	sin = (struct sockaddr_in *)rp->ai_addr;
	inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));

	return get(sd, rp, host, port, location);
}

FILE *uget(char *url)
{
	struct addrinfo *ai;
	ssize_t num;
	uint16_t port = 80;
	FILE *fp;
	char *server = NULL, *location = NULL;
	char *ptr;
	char buf[256];
	int header = 1;
	int sd;

	split(url, &server, &port, &location);
	if (!server || !location)
		return NULL;

	if (nslookup(server, port, &ai))
		return NULL;

	sd = hello(ai, port, location);
	if (-1 == sd)
		return NULL;

	fp = tmpfile();
	while ((num = recv(sd, buf, sizeof(buf) - 1, 0)) > 0) {
		buf[num] = 0;
		if (header) {
			if (!strstr(buf, "200 OK"))
				break;
			ptr = strstr(buf, "\r\n\r\n");
			if (!ptr)
				break;

			ptr += 4;
			fputs(ptr, fp);
			header = 0;
			continue;
		}
		fputs(buf, fp);
	}
	shutdown(sd, SHUT_RDWR);
	close(sd);

	rewind(fp);
	return fp;
}

#ifndef LOCALSTATEDIR
static int usage(void)
{
	printf("Usage: uget URL\n");
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fp;
	char buf[256];

	if (argc < 2)
		return usage();

	fp = uget(argv[1]);
	if (!fp)
		return 1;

	while (fgets(buf, sizeof(buf), fp))
		fputs(buf, stdout);
	fclose(fp);

	return 0;
}
#endif
