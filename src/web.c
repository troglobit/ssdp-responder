/* Micro web server for serving SSDP .xml file
 *
 * Copyright (c) 2017-2023  Joachim Wiberg <troglobit@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ssdp.h"

const char *xml =
	"<?xml version=\"1.0\"?>\r\n"
	"<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\r\n"
	" <specVersion>\r\n"
	"   <major>1</major>\r\n"
	"   <minor>0</minor>\r\n"
	" </specVersion>\r\n"
	" <device>\r\n"
	"  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\r\n"
	"  <friendlyName>%s</friendlyName>\r\n"
	"  <manufacturer>%s</manufacturer>\r\n%s"
	"  <modelName>%s</modelName>\r\n"
	"  <UDN>%s</UDN>\r\n"
	"  <presentationURL>%s</presentationURL>\r\n"
	" </device>\r\n"
	"</root>\r\n"
	"\r\n";

/* Peek into SOCK_STREAM on accepted client socket to figure out inbound interface */
static struct sockaddr_in *stream_peek(int sd, char *ifname, size_t iflen)
{
        static struct sockaddr_in sin;
        struct ifaddrs *ifaddr, *ifa;
        socklen_t len = sizeof(sin);

        if (-1 == getsockname(sd, (struct sockaddr *)&sin, &len))
                return NULL;

        if (-1 == getifaddrs(&ifaddr))
                return NULL;

        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
                size_t inlen = sizeof(struct in_addr);
                struct sockaddr_in *iin;

                if (!ifa->ifa_addr)
                        continue;

                if (ifa->ifa_addr->sa_family != AF_INET)
                        continue;

                iin = (struct sockaddr_in *)ifa->ifa_addr;
                if (!memcmp(&sin.sin_addr, &iin->sin_addr, inlen)) {
                        strlcpy(ifname, ifa->ifa_name, iflen);
                        break;
                }
        }

        freeifaddrs(ifaddr);

        return &sin;
}

static char *compose_url(char *addr)
{
	const char *fmt = url;
	static char buf[192];

	snprintf(buf, sizeof(buf), fmt, addr);
	return buf;
}

static char *compose_time(void)
{
       const char *rfc1123fmt = "%a, %d %b %Y %H:%M:%S GMT";
       static char buf[100];
       time_t now;

       now = time(NULL);
       strftime(buf, sizeof(buf), rfc1123fmt, gmtime(&now));

       return buf;
}

static int validate_http(int sd, char *http)
{
	if (!http || (strncmp(http, "HTTP/1.0", 8) != 0 &&
		      strncmp(http, "HTTP/1.1", 8) != 0)) {
		if (write(sd, "HTTP/1.1 400 Bad Request\r\n", 26) < 0)
			logit(LOG_WARNING, "Failed returning status 400 to client: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int respond(int sd, struct sockaddr_in *sin)
{
	struct pollfd pfd = {
		.fd = sd,
		.events = POLLIN,
	};
	const char *head = "HTTP/1.1 200 OK\r\n"
		"Date: %s\r\n"
		"Server: ssdp-responder/%s\r\n"
		"Content-Type: text/xml\r\n"
		"Connection: close\r\n"
		"\r\n";
	char manufacturer_url[192] = "";
	char mesg[1024], *reqline[3];
	char hostname[64];
	int rc, rcvd;

	/* Check for early disconnect or client timeout */
	rc = poll(&pfd, 1, 1000);
	if (rc <= 0) {
		if (rc == 0)
			errno = ETIMEDOUT;
		return -1;
	}

	memset(mesg, 0, sizeof(mesg));
	rcvd = recv(sd, mesg, sizeof(mesg) - 1, 0);
	if (rcvd <= 0) {
		if (rcvd == -1)
			logit(LOG_WARNING, "web recv() error: %s", strerror(errno));
		return -1;
	}
	mesg[rcvd] = 0;

	logit(LOG_DEBUG, "%s", mesg);
	reqline[0] = strtok(mesg, " \t\n");
	reqline[1] = strtok(NULL, " \t");
	reqline[2] = strtok(NULL, " \t\n");

	if (!reqline[0]) {
		return -1;
	} else if (strncmp(reqline[0], "HEAD", 5) == 0) {
		if (validate_http(sd, reqline[2]))
			return -1;

		snprintf(mesg, sizeof(mesg), head, compose_time(), VERSION);
		if (send(sd, mesg, strlen(mesg), 0) < 0)
			return -1;
	} else if (strncmp(reqline[0], "GET", 4) == 0) {
		if (validate_http(sd, reqline[2]))
			return -1;

		/* XXX: Add support for icon as well */
		if (!reqline[1] || !strstr(reqline[1], LOCATION_DESC)) {
			if (write(sd, "HTTP/1.1 404 Not Found\r\n", 24) < 0)
				logit(LOG_WARNING, "Failed returning status 404 to client: %s", strerror(errno));
			return -1;
		}

		gethostname(hostname, sizeof(hostname));
		if (mfrurl[0])
			snprintf(manufacturer_url, sizeof(manufacturer_url),
				 "  <manufacturerURL>%s</manufacturerURL>\r\n", mfrurl);

		logit(LOG_DEBUG, "Sending XML reply ...");
		rc = snprintf(mesg, sizeof(mesg), head, compose_time(), VERSION);
		snprintf(&mesg[rc], sizeof(mesg) - rc, xml,
			 hostname,
			 mfrnm,
			 manufacturer_url,
			 MODEL,
			 uuid,
			 compose_url(inet_ntoa(sin->sin_addr)));
		if (send(sd, mesg, strlen(mesg), 0) < 0) {
			logit(LOG_WARNING, "Failed sending file to client: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}

static void web_recv(int sd)
{
	int client;
	char ifname[IF_NAMESIZE + 1] = "UNKNOWN";
	struct sockaddr_in *sin;

	client = accept(sd, NULL, NULL);
	if (client < 0) {
		logit(LOG_ERR, "accept() error: %s", strerror(errno));
		return;
	}

	sin = stream_peek(client, ifname, sizeof(ifname));
	if (!sin) {
		logit(LOG_ERR, "Failed resolving client interface: %s", strerror(errno));
	} else if (!respond(client, sin))
		shutdown(client, SHUT_RDWR);

	close(client);
}

void web_init(void)
{
	struct sockaddr_in sin;
	int sd;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port        = htons(LOCATION_PORT);

	sd = socket(sin.sin_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (sd == -1) {
		logit(LOG_ERR, "Failed creating web socket: %s", strerror(errno));
		return;
	}

        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEADDR);
#ifdef SO_REUSEPORT
        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEPORT);
#endif

	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		logit(LOG_ERR, "Failed binding web socket: %s", strerror(errno));
		close(sd);
		return;
	}

	if (listen(sd, 10) != 0) {
		logit(LOG_ERR, "Failed setting web listen backlog: %s", strerror(errno));
		close(sd);
		return;
	}

	if (!ssdp_register(sd, NULL, (struct sockaddr *)&sin, NULL, web_recv)) {
		char host[20];

		inet_ntop(AF_INET, &sin.sin_addr, host, sizeof(host));
		logit(LOG_INFO, "Listening to HTTP connections on %s:%d", host, ntohs(sin.sin_port));
	}
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
