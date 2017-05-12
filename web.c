/* Micro web server for serving SSDP .xml file
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

#include <err.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ssdp.h"

#define ENABLE_SOCKOPT(sd, level, opt)					\
        do {								\
                int val = 1;						\
                if (setsockopt(sd, level, opt, &val, sizeof(val)) < 0)	\
                        warn("Failed enabling %s for web service", #opt); \
        } while (0);

char *root = "www/";
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
	"  <manufacturer>Westermo</manufacturer>\r\n"
	"  <manufacturerURL>http://www.westermo.com/</manufacturerURL>\r\n"
	"  <modelDescription>RedFox RFIR</modelDescription>\r\n"
	"  <modelName>RFIR</modelName>\r\n"
	"  <modelNumber>v5</modelNumber>\r\n"
	"  <modelURL>http://www.westermo.com/</modelURL>\r\n"
	"  <serialNumber>0000001</serialNumber>\r\n"
	"  <UDN>uuid:%s</UDN>\r\n"
	"  <UPC></UPC>\r\n"
	"  <presentationURL>http://%s</presentationURL>\r\n"
	" </device>\r\n"
	"</root>\r\n";

void register_socket(int sd, char *ifname, void (*cb)(int sd));

/* Peek into SOCK_STREAM on accepted client socket to figure out inbound interface */
static struct sockaddr_in *stream_peek(int sd, char *ifname)
{
        struct ifaddrs *ifaddr, *ifa;
        static struct sockaddr_in sin;
        socklen_t len = sizeof(sin);

        if (-1 == getsockname(sd, (struct sockaddr *)&sin, &len))
                return NULL;

        if (-1 == getifaddrs(&ifaddr))
                return NULL;

        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
                size_t len = sizeof(struct in_addr);
                struct sockaddr_in *iin;

                if (!ifa->ifa_addr)
                        continue;

                if (ifa->ifa_addr->sa_family != AF_INET)
                        continue;

                iin = (struct sockaddr_in *)ifa->ifa_addr;
                if (!memcmp(&sin.sin_addr, &iin->sin_addr, len)) {
                        strncpy(ifname, ifa->ifa_name, IF_NAMESIZE);
                        break;
                }
        }

        freeifaddrs(ifaddr);

        return &sin;
}

void respond(int sd, struct sockaddr_in *sin, socklen_t len)
{
	char hostname[64];
	char mesg[99999], *reqline[3], data_to_send[BYTES], path[99999];
	int rcvd, fd, bytes_read;

	memset(mesg, 0, sizeof(mesg));
	rcvd = recv(sd, mesg, sizeof(mesg), 0);
	if (rcvd <= 0) {
		warn("recv() error");
		goto error;
	}

	logit(LOG_DEBUG, "%s", mesg);
	reqline[0] = strtok(mesg, " \t\n");
	if (strncmp(reqline[0], "GET\0", 4) == 0) {
		reqline[1] = strtok(NULL, " \t");
		reqline[2] = strtok(NULL, " \t\n");
		if (strncmp(reqline[2], "HTTP/1.0", 8) != 0 && strncmp(reqline[2], "HTTP/1.1", 8) != 0) {
			if (write(sd, "HTTP/1.1 400 Bad Request\r\n", 26) < 0)
				warn("Failed returning status 400 to client");
			goto error;
		}

		strcpy(path, root);
		strcpy(&path[strlen(root)], reqline[1]);

		if (!strstr(path, LOCATION_DESC)) {
			if (write(sd, "HTTP/1.1 404 Not Found\r\n", 24) < 0)
				warn("Failed returning status 404 to client");
			goto error;
		}

		gethostname(hostname, sizeof(hostname));

		logit(LOG_DEBUG, "Sending XML reply ...");
		send(sd, "HTTP/1.1 200 OK\r\n\r\n", 19, 0);
		snprintf(data_to_send, sizeof(data_to_send), xml, hostname, uuid, inet_ntoa(sin->sin_addr));
		if (write(sd, data_to_send, strlen(data_to_send)) < 0)
			warn("Failed sending file to client");
	}

error:
	shutdown(sd, SHUT_RDWR);
	close(sd);
}

void web_recv(int sd)
{
	int client;
	char ifname[IF_NAMESIZE] = "UNKNOWN";
	socklen_t len;
	struct sockaddr_in sin, *sin_if;

	client = accept(sd, (struct sockaddr *)&sin, &len);
	if (client < 0) {
		warn("accept() error");
		return;
	}

	sin_if = stream_peek(client, ifname);

	respond(client, sin_if, len);
	shutdown(client, SHUT_RDWR);
	close(client);
}

void open_web_socket(char *ifname)
{
	int sd;
	struct sockaddr sa;
	struct sockaddr_in *sin;

	memset(&sa, 0, sizeof(sa));
	sa.sa_family = AF_INET;
	sin = (struct sockaddr_in *)&sa;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	sin->sin_port = htons(LOCATION_PORT);

	sd = socket(sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (sd == -1)
		err(1, "Failed creating web socket");

        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEADDR);
#ifdef SO_REUSEPORT
        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEPORT);
#endif

	if (bind(sd, &sa, sizeof(sa)) < 0)
		err(1, "Failed binding web socket");

	if (listen(sd, 10) != 0)
		err(1, "Failed setting web listen backlog");

	register_socket(sd, ifname, web_recv);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
