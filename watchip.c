#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include "iplist.h"
#include "watchip.h"

#define PENDING4 1
#define PENDING6 2
#define PENDINGLINK 4

struct watchip {
	struct iplist *iplist;
	int netlink_socket;
	int use_valid;
	int enable4;
	int enable6;
	int default_ttl;
	int max6_ttl;
	int pending_init;
	int filter_sense;
	struct filter_list *filter;
};

struct filter_list {
	struct filter_list *next;
	char *interface;
	int known;
	int id;
};

int
watchip_filter_add(struct filter_list **fp, char *name)
{
int len = strlen(name);
struct filter_list *result;

	if (!(result = malloc(sizeof(*result) + len + 1))) {
		fprintf(stderr, "watchip_filter_add: malloc failed\n");
		return 0;
	}
	memset(result, 0, sizeof(*result));
	result->interface = ((char *)result) + sizeof(*result);
	strcpy(result->interface, name);
	result->next = *fp;
	*fp = result;
	return 1;
}

static inline int
validate6(int len, void *a)
{
	if (len != 16) return 0;
	if (IN6_IS_ADDR_LOOPBACK(a)) return 0;
	if (IN6_IS_ADDR_MULTICAST(a)) return 0;
	if (IN6_IS_ADDR_LINKLOCAL(a)) return 0;
	return 1;
}

static inline int
validate4(int len, unsigned char *a)
{
	if (len != 4) return 0;
	if ((*a) == 127) return 0;
	if ((*a) == 0) return 0;
	if ((*a) >= 224) return 0;
	return 1;
}

static void
linkupdate(struct watchip *w, struct nlmsghdr *n)
{
int len = n->nlmsg_len;
struct ifinfomsg *ifi = NLMSG_DATA(n);
struct rtattr *rta;
char *link_name;
int isremove = 0;
struct filter_list *fcur;

	if (!(w->filter)) return;

	if ((n->nlmsg_type != RTM_NEWLINK) && (n->nlmsg_type != RTM_DELLINK))
		return;
	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0) return;

	if (n->nlmsg_type == RTM_DELLINK) isremove = 1;

	for (rta = IFLA_RTA(ifi); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type == IFLA_IFNAME) {
			link_name = (char *)RTA_DATA(rta);
			for (fcur = w->filter; fcur; fcur = fcur->next) {
				if (!strcmp(link_name, fcur->interface)) {
					if (isremove) {
						fcur->known = 0;
					} else {
						fcur->known = 1;
						fcur->id = ifi->ifi_index;
					}
					break;
				}
			}
		}
	}
}

static int
filter_match(struct watchip *w, int ifindex)
{
struct filter_list *fcur;

	if (w->filter_sense == 0) return 1;
	for (fcur = w->filter; fcur; fcur = fcur->next) {
		if (fcur->known && (fcur->id == ifindex)) {
			if (w->filter_sense == 1) return 1;
			return 0;
		}
	}
	if (w->filter_sense == 1) return 0;
	return 1;
}

static int
addrupdate(struct watchip *w, struct nlmsghdr *n)
{
int len = n->nlmsg_len;
struct ifaddrmsg *ifa = NLMSG_DATA(n);
struct rtattr *rta;
struct rtattr *rta_addr = NULL;
struct ifa_cacheinfo *ci;
int isremove = 0;
int ttl = -2;

	if ((n->nlmsg_type != RTM_NEWADDR) && (n->nlmsg_type != RTM_DELADDR))
		return 1;
	len -= NLMSG_LENGTH(sizeof(*ifa));
	if (len < 0) return 1;

	if (n->nlmsg_type == RTM_DELADDR) isremove = 1;
	if (ifa->ifa_flags & IFA_F_TENTATIVE) isremove = 1;
	if (ifa->ifa_flags & IFA_F_DEPRECATED) isremove = 1;

	if (!filter_match(w, ifa->ifa_index)) return 1;

	for (rta = IFA_RTA(ifa); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type == IFA_LOCAL) {
			rta_addr = rta;
		} else if (rta->rta_type == IFA_ADDRESS) {
			if (!rta_addr) rta_addr = rta;
		} else if (rta->rta_type == IFA_CACHEINFO) {
			ci = RTA_DATA(rta);
			if (w->use_valid) {
				if (ci->ifa_valid == -1) {
					ttl = w->max6_ttl;
				} else if (ci->ifa_valid >= 0) {
					ttl = ci->ifa_valid;
				}
			} else {
				if (ci->ifa_prefered == -1) {
					ttl = w->max6_ttl;
				} else if (ci->ifa_prefered >= 0) {
					ttl = ci->ifa_prefered;
				}
			}
			if (ci->ifa_prefered == 0) isremove = 1;
			if (ci->ifa_valid == 0) isremove = 1;
		}
	}
	if (ttl == -2) {
		if (ifa->ifa_family == AF_INET6) {
			return 1;	/* no lifetime information -- ignore address */
		} else {
			ttl = w->default_ttl;
		}
	}
	if (!rta_addr) return 1;

	switch (ifa->ifa_family) {
		case AF_INET6:
			if (!validate6(RTA_PAYLOAD(rta_addr), RTA_DATA(rta_addr))) return 1;
			break;
		case AF_INET:
			if (!validate4(RTA_PAYLOAD(rta_addr), RTA_DATA(rta_addr))) return 1;
			break;
	}
	return
		iplist_notify(
			w->iplist,
			isremove,
			ttl,
			ifa->ifa_family,
			RTA_DATA(rta_addr)
		);
}

static int
dump_request(int fd, int family, int type)
{
struct {
	struct nlmsghdr nlh;
	struct rtgenmsg g;
} req;
struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 1;
	req.g.rtgen_family = family;

	return sendto(fd, (void *)(&req), sizeof(req), 0,
		(struct sockaddr *)(&nladdr), sizeof(nladdr));
}

static int
request_one_dump(struct watchip *w)
{
	if (w->pending_init & PENDINGLINK) {
		w->pending_init &= ~PENDINGLINK;
		if (dump_request(w->netlink_socket, AF_UNSPEC, RTM_GETLINK) < 0) {
			perror("sendto(netlink AF_INET6)");
			return 0;
		}
	} else if (w->pending_init & PENDING6) {
		w->pending_init &= ~PENDING6;
		if (dump_request(w->netlink_socket, AF_INET6, RTM_GETADDR) < 0) {
			perror("sendto(netlink AF_INET6)");
			return 0;
		}
	} else if (w->pending_init & PENDING4) {
		w->pending_init &= ~PENDING4;
		if (dump_request(w->netlink_socket, AF_INET, RTM_GETADDR) < 0) {
			perror("sendto(netlink AF_INET)");
			return 0;
		}
	}
	return 1;
}

static int
watchip_run(struct watchip *w)
{
int len;
struct nlmsghdr *nh;
struct iovec iov;
struct msghdr msg;
struct sockaddr_nl sa;
char buf[4096];

	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = buf;

	for (;;) {
		iov.iov_len = sizeof(buf);

		if ((len = recvmsg(w->netlink_socket, &msg, 0)) < 0) {
			perror("recvmsg() on netlink socket");
			return 0;
		}

		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
			switch (nh->nlmsg_type) {
				case RTM_NEWADDR:
				case RTM_DELADDR:
					if (!addrupdate(w, nh)) return 0;
					break;
				case RTM_NEWLINK:
				case RTM_DELLINK:
					linkupdate(w, nh);
					break;
				case NLMSG_DONE:
					if ((w->pending_init) == 0) {
						iplist_rebuild_end(w->iplist);
						return 1;
					} else {
						if (!request_one_dump(w)) return 0;
					}
					break;
				case NLMSG_ERROR:
					perror("Got NLMSG_ERR from netlink");
					return 0;
				case NLMSG_OVERRUN:
					perror("Got NLMSG_OVERRUN from netlink");
					return 0;
			}
		}
	}
}

static int
request_addresses(struct watchip *w)
{
	w->pending_init = 0;
	if ((w->filter_sense != 0) && (w->filter)) w->pending_init |= PENDINGLINK;
	if (w->enable6) w->pending_init |= PENDING6;
	if (w->enable4) w->pending_init |= PENDING4;
	iplist_rebuild_start(w->iplist);
	return request_one_dump(w);
}

struct watchip *
watchip_start(
	struct iplist *ilist,
	int enable4,
	int enable6,
	int use_valid,
	int default_ttl,
	int max6_ttl,
	int filter_sense,
	struct filter_list *filter
)
{
struct watchip *w;
struct sockaddr_nl bindaddr;
int sndbuf = 32768;
int rcvbuf = 32768;

	if (!(w = malloc(sizeof(*w)))) {
		perror("malloc");
		return NULL;
	}

	memset(w, 0, sizeof(*w));
	w->iplist = ilist;
	w->enable4 = enable4;
	w->enable6 = enable6;
	w->use_valid = use_valid;
	w->default_ttl = default_ttl;
	w->max6_ttl = max6_ttl;
	w->filter_sense = filter_sense;
	w->filter = filter;

	if ((w->netlink_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		perror("socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)");
		free(w);
		return NULL;
	}

        if (setsockopt(w->netlink_socket, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
                perror("setsockopt(...SO_SNDBUF...)");
		close(w->netlink_socket);
		free(w);
		return NULL;
        }

        if (setsockopt(w->netlink_socket, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
                perror("setsockopt(...SO_RCVBUF...)");
		close(w->netlink_socket);
		free(w);
		return NULL;
        }

	memset(&bindaddr, 0, sizeof(bindaddr));
	bindaddr.nl_family = AF_NETLINK;
	bindaddr.nl_groups = 0;

	if ((filter_sense != 0) && (filter)) bindaddr.nl_groups |= 1 << (RTNLGRP_LINK-1);
	if (enable6) bindaddr.nl_groups |= 1 << (RTNLGRP_IPV6_IFADDR-1);
	if (enable4) bindaddr.nl_groups |= 1 << (RTNLGRP_IPV4_IFADDR-1);

	if (bind(w->netlink_socket, (struct sockaddr *)(&bindaddr), sizeof(bindaddr)) < 0) {
		perror("bind(..RTNLGRP_IPV4_IFADDR and/or RTNLGRP_IPV6_IFADDR..)");
		close(w->netlink_socket);
		free(w);
		return NULL;
        }

	if (!request_addresses(w)) {
		close(w->netlink_socket);
		free(w);
		return NULL;
	}

	if (watchip_run(w) == 0) {
		close(w->netlink_socket);
		free(w);
		return NULL;
	}

	return w;
}

void
watchip(struct watchip *w)
{
	for (;;) {
		if (watchip_run(w) == 0) {
			/* Failure of some kind */
			/* reset list of known addresses */
			while (!request_addresses(w)) sleep(1);
		}
	}

	close(w->netlink_socket);
	free(w);
}
