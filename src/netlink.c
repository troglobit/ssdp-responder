/* Linux netlink address monitor
 *
 * Copyright (c) 2023  Joachim Wiberg <troglobit@gmail.com>
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

#include "ssdp.h"

#ifdef HAVE_LINUX_NETLINK_H
#include <time.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static unsigned char buffer[4094];
static time_t latest_change;

/*
 * On IP address change we potentially get a LOT of netlink messages.
 * This (very) limited netlink monitor considers any change but also
 * smooths out the changes by scheduling SIGALRM in five seconds on
 * each change.  If more changes come in during that time, the timer
 * is reset to five seconds for each change.
 */
static void parse_rta(struct nlmsghdr *nlmsg)
{
	struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlmsg);
	struct rtattr *rta = IFA_RTA(ifa);
	int la = IFA_PAYLOAD(nlmsg);

	while (la && RTA_OK(rta, la)) {
		if (rta->rta_type == IFA_LOCAL) {
			alarm(5);
			break;
		}

		rta = RTA_NEXT(rta, la);
	}
}

static void netlink_recv(int sd)
{
	struct nlmsghdr *nlmsg;
	ssize_t len;

	while ((len = recv(sd, buffer, sizeof(buffer), 0)) == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			continue;
		default:
			break;
		}
	}

	if (len == 0 || (size_t)len > sizeof(buffer))
		return;

	nlmsg = (struct nlmsghdr *)buffer;
	if (nlmsg->nlmsg_flags & MSG_TRUNC)
		return;

	while ((NLMSG_OK(nlmsg, len)) && (nlmsg->nlmsg_type != NLMSG_DONE)) {
		switch (nlmsg->nlmsg_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
			parse_rta(nlmsg);
			break;
		default:
			break;
		}

		nlmsg = NLMSG_NEXT(nlmsg, len);
	}
}

int netlink_init(void)
{
	struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_IPV4_IFADDR, /* | RTMGRP_IPV6_IFADDR, */
	};
	int sd;

	sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sd == -1) {
		logit(LOG_ERR, "Failed creating netlink socket: %s", strerror(errno));
		return -1;
	}

	if (bind(sd, (struct sockaddr *)&snl, sizeof(snl)) == -1) {
		logit(LOG_ERR, "Failed binding to netlink socket: %s", strerror(errno));
		close(sd);
		return -1;
	}

	latest_change = time(NULL);
	if (ssdp_register(sd, NULL, (struct sockaddr *)&snl, NULL, netlink_recv)) {
		close(sd);
		return -1;
	}

	return 0;
}

#else
int netlink_init(void)
{
	return -1;
}
#endif /* HAVE_LINUX_NETLINK_H */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
