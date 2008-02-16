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
	struct ip_filter_list *filter4;
	struct ip_filter_list *filter6;
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

struct ip_filter_list {
	struct ip_filter_list *next;
	int accept;
	int plen;
	unsigned char addr[16];
};

int
watchip_intf_filter_add(struct watchip_param *p, char *arg)
{
char *s;
int len;
int filter_sense;
struct filter_list *result;

	while (arg) {
		if (s = strchr(arg, ',')) *(s++) = 0;

		filter_sense = 1;
		if (arg[0] == '!') {
			filter_sense = -1;
			arg++;
		}
		if (*arg) {
			if (
				(p->intf_filter_sense) != 0 &&
				(filter_sense != (p->intf_filter_sense))
			) {
				fprintf(stderr,
					"%s: cannot mix \"-i include\" with \"-i !exclude\"\n",
					p->progname
				);
				return 1;
			}
			p->intf_filter_sense = filter_sense;

			len = strlen(arg);
			if (!(result = malloc(sizeof(*result) + len + 1))) {
				fprintf(stderr, "%s: watchip_filter_add: malloc failed\n", p->progname);
				return 2;
			}
			memset(result, 0, sizeof(*result));
			result->interface = ((char *)result) + sizeof(*result);
			strcpy(result->interface, arg);
			result->next = p->intf_filter;
			p->intf_filter = result;
		} else {
			fprintf(stderr, "%s: need an interface name after -i\n", p->progname);
		}
		arg = s;
	}

	return 0;
}

int
watchip_ip_filter_add(struct watchip_param *p, char *arg)
{
char *s, *q, *r;
char *arg_copy;
int plen;
int filter_sense;
struct ip_filter_list *new;
struct ip_filter_list **fp;

	if (!(arg_copy = strdup(arg))) {
		fprintf(stderr, "%s: watchip_ip_filter_add: malloc failed\n", p->progname);
		return 2;
	}
	arg = arg_copy;

	while (arg) {
		if (s = strchr(arg, ',')) *(s++) = 0;

		filter_sense = 1;
		if (arg[0] == '!') {
			filter_sense = 0;
			arg++;
		}
		if (*arg) {
			if (!(new = malloc(sizeof(*new)))) {
				fprintf(stderr, "%s: watchip_ip_filter_add: malloc failed\n", p->progname);
				free(arg_copy);
				return 2;
			}
			memset(new, 0, sizeof(*new));

			plen = -1;
			if (q = strchr(arg, '/')) {
				*(q++) = 0;
				if (*q) {
					plen = strtoul(q, &r, 10);
					if (*r) plen = -1;
				}
				if ((plen < 0) || (plen > 128)) {
					q[-1] = '/';
					fprintf(stderr, "%s: watchip_ip_filter_add: cannot parse address \"%s\", syntax is addr/prefix-length\n", p->progname, arg);
					free(new);
					free(arg_copy);
					return 1;
				}
			}

			if (strchr(arg, '.')) {
				if (strchr(arg, ':')) {
					fprintf(stderr,
						"%s: watchip_ip_filter_add: address \"%s\" contains both \".\" and \":\"\n"
						"%s: IPv4 addresses should contain only \".\", IPv6, only \":\"\n",
						p->progname, arg, p->progname
					);
					free(new);
					free(arg_copy);
					return 1;
				}
				fp = &(p->filter4);

				if (inet_pton(AF_INET, arg, &(new->addr)) < 1) {
					fprintf(stderr,
						"%s: watchip_ip_filter_add: cannot parse IPv4 address \"%s\"\n",
						p->progname, arg
					);
					free(new);
					free(arg_copy);
					return 1;
				}

				new->plen = ((plen < 0) || (plen > 32)) ? 32 : plen;
			} else if (strchr(arg, ':')) {
				fp = &(p->filter6);

				if (inet_pton(AF_INET6, arg, &(new->addr)) < 1) {
					fprintf(stderr,
						"%s: watchip_ip_filter_add: cannot parse IPv6 address \"%s\"\n",
						p->progname, arg
					);
					free(new);
					free(arg_copy);
					return 1;
				}

				new->plen = (plen < 0) ? 128 : plen;
			} else {
				fprintf(stderr,
					"%s: watchip_ip_filter_add: cannot interpret \"%s\" as an IP address\n",
					p->progname, arg
				);
				free(new);
				free(arg_copy);
				return 1;
			}

			new->accept = filter_sense;

			new->next = *fp;
			*fp = new;
		} else {
			fprintf(stderr, "%s: need an interface name after -a\n", p->progname);
		}
		arg = s;
	}
	
	free(arg_copy);
	return 0;
}

static void
filter_free(struct ip_filter_list *l)
{
struct ip_filter_list *tmp;

	while (l) {
		tmp = l->next;
		free(l);
		l = tmp;
	}
}

/* If the last entry in a filter is a reject, then the user surely
   intended for the filter to accept by default (else the last entry
   would be a noop) -> add an entry to accept everything

   Likewise, If the last entry in a filter is an accept, then do
   nothing
*/
static int
maybe_default_accept(struct ip_filter_list **fp)
{
struct ip_filter_list *new;

	if ((*fp)->accept > 0) return 1;

	if (!(new = malloc(sizeof(*new)))) {
		fprintf(stderr, "maybe_default_accept: malloc failure\n");
		return 0;
	}
	memset(new, 0, sizeof(*new));

	new->accept = 1;
	new->next = *fp;
	*fp = new;
	return 1;
}

static struct ip_filter_list *
reverselist(struct ip_filter_list *l1)
{
struct ip_filter_list *l2 = NULL;
struct ip_filter_list *tmp;

	while (l1) {
		tmp = l1;
		l1 = l1->next;
		tmp->next = l2;
		l2 = tmp;
	}
	return l2;
}

static void
dumplist(struct ip_filter_list *l, int family)
{
char buf[64];

	while (l) {
		inet_ntop(family, &(l->addr), buf, sizeof(buf));
		fprintf(stdout, "  %s %s/%d\n",
			(l->accept > 0) ? "permit" : "deny  ",
			buf, l->plen
		);
		l = l->next;
	}

	fprintf(stdout, "(implicit deny)\n");
}

int
watchip_filter_finished(struct watchip_param *p, int verbose)
{
int n;

	if (p->enable4) {
		if (!(p->filter4)) {
			if ((n = watchip_ip_filter_add(p, "!192.168.0.0/16,!172.16.0.0/12,!10.0.0.0/8")) > 0) {
				return n;
			}
		}
	} else {
		if (p->filter4) {
			fprintf(stderr, "%s: warning: at least one IPv4 address given in filter but IPv4 is disabled.\n", p->progname);
			filter_free(p->filter4);
			p->filter4 = NULL;
		}
	}

	if (p->enable6) {
		if (!(p->filter6)) {
			if ((n = watchip_ip_filter_add(p, "!fc00::/7")) > 0) {
				return n;
			}
		}
	} else {
		if (p->filter6) {
			fprintf(stderr, "%s: warning: at least one IPv6 address given in filter but IPv6 is disabled.\n", p->progname);
			filter_free(p->filter6);
			p->filter4 = NULL;
		}
	}

	if (!maybe_default_accept(&(p->filter4))) return 2;
	if (!maybe_default_accept(&(p->filter6))) return 2;

	p->filter4 = reverselist(p->filter4);
	p->filter6 = reverselist(p->filter6);

	if (verbose) {
		fprintf(stdout, "IPv4 IP address filter:\n");
		dumplist(p->filter4, AF_INET);

		fprintf(stdout, "IPv6 IP address filter:\n");
		dumplist(p->filter6, AF_INET6);
	}
	return 0;
}

static int
ip_filter_match(struct ip_filter_list *l, unsigned char *a)
{
int mask;

	for (; l; l = l->next) {
		if (l->plen >= 8) {
			if (memcmp(a, l->addr, l->plen >> 3)) continue;
		}
		if (l->plen & 7) {
			mask = (~((256 >> (l->plen & 7)) - 1)) & 255;
			if (
				(l->addr[l->plen >> 3] & mask) !=
				(a[l->plen >> 3] & mask)
			) continue;
		}
		return l->accept;
	}
	return 0;	/* implicit deny */
}

static inline int
validate6(struct watchip *w, int len, void *a)
{
	if (len != 16) return 0;
	if (IN6_IS_ADDR_LOOPBACK(a)) return 0;
	if (IN6_IS_ADDR_MULTICAST(a)) return 0;
	if (IN6_IS_ADDR_LINKLOCAL(a)) return 0;

	return ip_filter_match(w->filter6, a);
}

static inline int
validate4(struct watchip *w, int len, unsigned char *a)
{
	if (len != 4) return 0;
	if ((*a) == 127) return 0;
	if ((*a) == 0) return 0;
	if ((*a) >= 224) return 0;

	return ip_filter_match(w->filter4, a);
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
			if (!validate6(w, RTA_PAYLOAD(rta_addr), RTA_DATA(rta_addr))) return 1;
			break;
		case AF_INET:
			if (!validate4(w, RTA_PAYLOAD(rta_addr), RTA_DATA(rta_addr))) return 1;
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
	if (w->filter6) w->pending_init |= PENDING6;
	if (w->filter4) w->pending_init |= PENDING4;
	iplist_rebuild_start(w->iplist);
	return request_one_dump(w);
}

struct watchip *
watchip_start(
	struct iplist *ilist,
	struct watchip_param *param,
	int use_valid,
	int default_ttl,
	int max6_ttl
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
	w->filter4 = param->filter4;
	w->filter6 = param->filter6;
	w->use_valid = use_valid;
	w->default_ttl = default_ttl;
	w->max6_ttl = max6_ttl;
	w->filter_sense = param->intf_filter_sense;
	w->filter = param->intf_filter;

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

	if (((w->filter_sense) != 0) && (w->filter)) bindaddr.nl_groups |= 1 << (RTNLGRP_LINK-1);
	if (w->filter6) bindaddr.nl_groups |= 1 << (RTNLGRP_IPV6_IFADDR-1);
	if (w->filter4) bindaddr.nl_groups |= 1 << (RTNLGRP_IPV4_IFADDR-1);

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
