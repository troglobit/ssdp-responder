/* SSDP scanner
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

#include "ssdp.h"
#include "queue.h"

#include <err.h>
#ifdef HAVE_TERMIOS_H
# include <termios.h>
#endif


struct host {
	LIST_ENTRY(host) link;

	char *name;
	char *url;
};

LIST_HEAD(, host) hl = LIST_HEAD_INITIALIZER();

volatile sig_atomic_t running = 1;
#ifdef HAVE_TERMIOS_H
struct termios term;
#endif
static int atty;
static int json;
static int once;

extern FILE *uget(char *url);


static void hidecursor(void)
{
#ifdef HAVE_TERMIOS_H
	struct termios c;
#endif

	if (!atty)
		return;

#ifdef HAVE_TERMIOS_H
	if (tcgetattr(0, &term)) {
		atty = 0;
		return;
	}
	c = term;
	c.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &c);
#endif
	fputs("\e[?25l", stdout);
}

static void showcursor(void)
{
	if (!atty)
		return;

#ifdef HAVE_TERMIOS_H
	tcsetattr(0, TCSANOW, &term);
#endif
	fputs("\e[?25h", stdout);
}

static int host(char *name, char *url)
{
	struct host *h;

	if (!name || !url)
		return 1;

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
//	const char *style = ".oOOo.";
	const char *style = "\\-/|";
//	const char *style = ">v<^";
	static unsigned int i = 0;
	size_t num = 4;

	if (!atty || json)
		return;

//	printf("%u %% %zd = %lu (%u / %zd = %lu)\n", i, num, i % num, i, num, i / num);

	putchar(style[i++ % num]);
	printf("\b");
	fflush(stdout);
}

static void ssdp_scan(struct ifsock *ifs, int arg)
{
	struct sockaddr_in sin;
	char buf[200];
	ssize_t num;
	int len;

	(void)arg;
	if (!ifs || ifs->sd == -1)
		return;

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

	num = sendto(ifs->sd, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin));
	if (num < 0)
		warn("Failed sending SSDP M-SEARCH");
}

static char *find(char *buf, const char *search)
{
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
	char *ptr, *end;
	char tag[20];
	size_t len;

	len = snprintf(tag, sizeof(tag), "<%s>", tagn);
	ptr = strstr(buf, tag);
	if (!ptr)
		return 0;
	ptr += len;

	len = snprintf(tag, sizeof(tag), "</%s>", tagn);
	end = strstr(buf, tag);
	if (end)
		*end = 0;

	strlcpy(val, ptr, vlen);

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
		if (!nm[0] && xml(buf, "friendlyName", nm, sizeof(nm)))
			*name = nm;
		if (!uri[0] && xml(buf, "presentationURL", uri, sizeof(uri)))
			*url = uri;

		if (*name && *url)
			break;
	}
}

static void print(char *name, char *url)
{
	if (json)
		printf("%s  {\n"
		       "    \"name\": \"%s\",\n"
		       "    \"url\": \"%s\"\n"
		       "  }", once++ ? ",\n" : "", name, url);
	else
		printf("\r+ %-40s  %s\n", name, url);
}

static void printsrv(char *srv, char *loc)
{
	char *name = NULL, *url = NULL;
	char *copy;
	FILE *fp;

	/* Save copy in case of short/empty presentationURL */
	copy = strdup(loc);
	if (!copy)
		return;

	if (strncmp(loc, "http", 4))
		goto fallback;

	fp = uget(loc);
	if (!fp) {
	fallback:
		print(trim(srv), trim(loc));
		free(copy);
		return;
	}

	parse(fp, &name, &url);
	fclose(fp);

	if (!name || !url) {
		free(copy);
		return;
	}

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

	if (!host(name, url))
		print(name, url);

	free(copy);
}

static void ssdp_read(int sd)
{
	char buf[512];
	ssize_t len;
	char *loc;
	char *srv;

	memset(buf, 0, sizeof(buf));
	len = recv(sd, buf, sizeof(buf) - 1, 0);
	if (len <= 0)
		return;

	buf[len] = 0;
	logit(LOG_DEBUG, "%s(): buf[%s]", __func__, buf);

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
	(void)signo;
	running = 0;
}

static int usage(int code)
{
	printf("Usage: ssdp-scan [-hj] [-l LEVEL] [-t SEC] [IFACE [IFACE ...]]\n"
	       "\n"
	       "    -h        This help text\n"
	       "    -j        JSON output, best used with -t SEC option"
	       "    -l LEVEL  Set log level: none, err, notice (default), info, debug\n"
	       "    -t SEC    Timeout and exit after SEC seconds.\n"
	       "\n"
	       "Bug report address : %s\n", PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
        printf("Project homepage   : %s\n", PACKAGE_URL);
#endif

	return code;
}

int main(int argc, char *argv[])
{
	int throttle = 1;
	int timeout = 0;
	int c;

	log_level = LOG_NOTICE;
	atty = isatty(STDOUT_FILENO);

	while ((c = getopt(argc, argv, "hjl:t:")) != EOF) {
		switch (c) {
		case 'h':
			return usage(0);

		case 'j':
			json = 1;
			break;

		case 'l':
			log_level = log_str2lvl(optarg);
			if (-1 == log_level)
				return usage(1);
			break;

		case 't':
			timeout = atoi(optarg);
			break;

		default:
			return usage(1);
		}
	}

	signal(SIGINT, bye);
	signal(SIGALRM, bye);

	log_init(0);

	if (timeout > 0) {
		warnx("Auto-stop in %d seconds ...", timeout);
		alarm(timeout);
	}

	if (ssdp_init(1, 0, &argv[optind], argc - optind, ssdp_read) < 1)
		return 1;

	hidecursor();
	progress();

	if (json)
		printf("[\n");

	ssdp_foreach(ssdp_scan, 1);

	while (running) {
		progress();

		switch (ssdp_poll(100)) {
		case -1:
			if (errno == EINTR)
				break;

			err(1, "Unrecoverable error");
			break;

		case 0:
			if (!(throttle++ % 20))
				ssdp_foreach(ssdp_scan, 0);
			break;

		default:
			break;
		}
	}

	if (json)
		printf("%s]\n", once ? "\n" : "");

	showcursor();
	log_exit();

	return ssdp_exit();
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
