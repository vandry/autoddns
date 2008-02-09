#include <stdlib.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "dnsquery.h"

/* This is not a general purpose DNS querier, it
   only handles a small number of records of the 3
   or 4 things we need */

struct dns_qcache {
	struct dns_qcache *next;
	/* 's' = SOA MNAME, 'c' = CNAME, 'h' = our hostname, 'r' = res_init */
	char type;
	char *domain;
	time_t expire_time;
	int positive;
	char *value;
};

static struct dns_qcache *qcache = NULL;
static int verbose = 0;

void
dnsquery_set_verbose(int v)
{
	verbose = v;
}

static struct dns_qcache *
find_in_cache(char type, char *domain)
{
struct dns_qcache *cur, *tmp, *found, **prevp;
time_t now;

	prevp = &qcache;
	time(&now);
	found = NULL;
	while (cur = *prevp) {
		if (cur->expire_time < now) {
			tmp = cur->next;
			*prevp = tmp;
			if (cur->domain) free(cur->domain);
			if (cur->value) free(cur->value);
			free(cur);
			cur = tmp;
			continue;
		}
		if (cur->type == type) {
			if (domain) {
				if (!strcmp(domain, cur->domain)) {
					found = cur;
				}
			} else {
				found = cur;
			}
		}
		prevp = &(cur->next);
	}
	return found;
}

static struct dns_qcache *
query_item(char type, char *domain, int (*callback)(struct dns_qcache *))
{
struct dns_qcache *found;
int ttl;

	if (verbose) {
		fprintf(stderr, "Query for ");
		switch (type) {
			case 'r':
				fprintf(stderr, "res_init()");
				break;
			case 'h':
				fprintf(stderr, "local hostname");
				break;
			case 's':
				fprintf(stderr, "SOA MNAME \"%s\"", domain);
				break;
			case 'c':
				fprintf(stderr, "CNAME \"%s\"", domain);
				break;
		}
		fprintf(stderr, "...");
	}
	if (found = find_in_cache(type, domain)) {
		if (verbose) {
			if (found->value) {
				fprintf(stderr, " (cached) \"%s\"\n", found->value);
			} else if (found->positive) {
				fprintf(stderr, " (cached) ok\n");
			} else {
				fprintf(stderr, " (cached) not found\n");
			}
		}
		return found;
	}

	if (!(found = malloc(sizeof(*found)))) return NULL;
	memset(found, 0, sizeof(*found));

	found->type = type;
	if (domain) {
		if (!(found->domain = strdup(domain))) {
			free(found);
			return NULL;
		}
	}

	ttl = callback(found);
	if (ttl < 0) {
		if (verbose) fprintf(stderr, " failed.\n");
		if (found->domain) free(found->domain);
		free(found);
		return NULL;
	}

	if (verbose) {
		if (found->value) {
			fprintf(stderr, " \"%s\" TTL %d\n", found->value, ttl);
		} else if (found->positive) {
			fprintf(stderr, " ok TTL %d\n", ttl);
		} else {
			fprintf(stderr, " not found TTL %d\n", ttl);
		}
	}

	found->expire_time = time(NULL) + ttl;
	found->next = qcache;
	qcache = found;

	return found;
}

static int
res_init_callback(struct dns_qcache *c)
{
	if (res_init() < 0) return -1;
	_res.options &= ~(RES_DEFNAMES|RES_DNSRCH);
	c->positive = 1;
	return 86400;
}
static inline int
do_res_init(void)
{
	if (!query_item('r', NULL, res_init_callback)) return 0;
	return 1;
}

static int
local_hostname_callback(struct dns_qcache *c)
{
char buf[4096];
struct hostent *he;
int len;

	if (gethostname(buf, sizeof(buf)) < 0) return -1;
	if (!(he = gethostbyname(buf))) return -1;
	len = strlen(he->h_name);
	if (!(c->value = malloc(len+2))) return -1;
	if (he->h_name[len-1] == '.') {
		strcpy(c->value, he->h_name);
	} else {
		sprintf(c->value, "%s.", he->h_name);
	}
	c->positive = 1;
	return 86400;
}
static inline char *
local_hostname(void)
{
struct dns_qcache *c;

	if (!(c = query_item('h', NULL, local_hostname_callback))) return NULL;
	return c->value;
}

static int
domain_length(unsigned char *buf, int startpos, int len, int seed)
{
int result = seed;
int pos = startpos;

	for (;;) {
		if (pos >= len) return -1;
		if (buf[pos] == 0) return result;
		if (buf[pos] < 64) {
			if ((pos + buf[pos] + 1) >= len) return -1;
			result += buf[pos] + 1;
			pos += buf[pos] + 1;
		} else if (buf[pos] >= 192) {
			if ((pos + 2) > len) return -1;
			return domain_length(buf,
				(buf[pos] & 0x3f) | buf[pos+1],
				startpos, result
			);
		} else {
			return -1;
		}
	}
}

/* all the bounds have already been checked when we
   precalculated the length */
static void
uncompress_domain(unsigned char *buf, int pos, char *result)
{
	while (buf[pos]) {
		if (buf[pos] < 64) {
			memcpy(result, buf+pos+1, buf[pos]);
			result += buf[pos];
			*(result++) = '.';
			pos += buf[pos] + 1;
		} else {
			pos = (buf[pos] & 0x3f) | buf[pos+1];
		}
	}
}

#define QDCOUNT 0
#define ANCOUNT 1
#define NSCOUNT 2
#define ARCOUNT 3

#define skipname							\
	for (;;) {							\
		if (pos >= len) return -1; /* short packet */		\
		if (buf[pos] == 0) {					\
			pos++;						\
			break;						\
		}							\
		if (buf[pos] < 64) {					\
			/* do bounds check at the top of the loop */	\
			pos += buf[pos] + 1;				\
		} else if (buf[pos] >= 192) {				\
			if ((pos+1) >= len) return -1; /* need 2 */	\
			pos += 2;					\
			break;						\
		} else {						\
			return -1; /* yuck protocol error */		\
		}							\
	}

static int dns_callback(struct dns_qcache *c)
{
int len, result_len;
int counts[4];
int pos, i, ttl;
unsigned char querybuf[4096];
unsigned char buf[4096];

	len = res_mkquery(ns_o_query, c->domain, ns_c_in,
		(c->type == 's') ? ns_t_soa : ns_t_cname,
		NULL, 0, NULL, querybuf, sizeof(querybuf));
	if (len < 0) {
		if (verbose) fprintf(stderr, "res_mkquery() failed");
		return -1;
	}

	len = res_send(querybuf, len, buf, sizeof(buf));

	/* is it less than the DNS header length? */
	if (len < 12) {
		if (verbose) fprintf(stderr, "res_send() failed or response too short");
		return -1;
	}

	if ((buf[2] & 0xf8) != 0x80) {
		if (verbose) fprintf(stderr, "expected response to query, got somethingelse");
		return -1; /* wrong kind of packet */
	}
	if (
		((buf[3] & 15) != ns_r_nxdomain) &&
		((buf[3] & 15) != ns_r_noerror)
	) {
		if (verbose) fprintf(stderr, "DNS rcode=%d", buf[3] & 15);
		return -1;	/* unacceptable response code */
	}

	for (i = 0; i < 4; i++) {
		counts[i] = (buf[(i<<1)+4] << 8) + buf[(i<<1)+5];
	}

	pos = 12;

	/* skip over the questions */
	while (counts[QDCOUNT]) {
		skipname;
		pos += 4;	/* type and class */
		if (pos > len) {
			if (verbose) fprintf(stderr, "DNS truncated in query");
			return -1;	/* packet short */
		}
		counts[QDCOUNT]--;
	}

	if (counts[ANCOUNT] || counts[NSCOUNT]) {
		/* whether we have an answer or an auth record, either
		   way, skip its name */
		skipname;
		/* and a type&class + TTL + datalen are required */
		if ((pos+10) > len) return -1;	/* packet short */

		if (((buf[pos+2] << 8) | buf[pos+3]) != ns_c_in)
			return -1;	/* cannot handle non IN class */
	}

	if (counts[ANCOUNT]) {
		/* take only the first answer. We only ever query for
		   CNAME and SOA which there should only be one of anyway */
		c->positive = 1;
		ttl = (buf[pos+4] << 24) | (buf[pos+5] << 16) |
			(buf[pos+6] << 8) | buf[pos+7];

		/* get datalen */
		i = (buf[pos+8] << 8) | buf[pos+9];
		pos += 10;	/* move cursor to RDATA */
		if ((pos + i) > len) return -1;	/* too short */

		/* we need nothing further beyond the end of this
		   RDATA so go no further (shorten length) */
		len = pos + i;

		/* Extract the name from here */

		result_len = domain_length(buf, pos, len, 0);

		if (result_len < 0) {
			if (verbose) fprintf(stderr, "error extracting domain name from answer");
			return -1;
		}

		if (!(c->value = malloc(result_len + 1))) {
			fprintf(stderr, "dns_callback: malloc failure\n");
			return -1;
		}
		c->value[result_len] = 0;

		uncompress_domain(buf, pos, c->value);

		return ttl;
	} else if (counts[NSCOUNT]) {
		/* No answer. We are just looking for the TTL */
		if (((buf[pos] << 8) | buf[pos+1]) != ns_t_soa)
			/* what's this, not SOA in authority section? */
			return -1;
		i = ((buf[pos+8] << 8) | buf[pos+9]); /* datalen */
		pos += i + 10;
		if (pos > len) return -1;	/* packet short */
		if (i < 4) return -1;	/* SOA record not long enough */

		/* return the TTL from the SOA record (NCACHE TTL) */
		return (buf[pos-4] << 24) | (buf[pos-3] << 16) |
			(buf[pos-2] << 8) | buf[pos-1];
	}

	if (verbose) fprintf(stderr, "DNS response incomplete (no answer or authority section)");
	return -1;
}

char *
canonical_hostname(void)
{
char *hostname;
struct dns_qcache *c;
int tries = 8;

	if (!(hostname = local_hostname())) return NULL;
	if (!do_res_init()) return NULL;

	while (tries-- > 0) {
		if (!(c = query_item('c', hostname, dns_callback))) return NULL;
		if (!(c->positive)) return hostname;
		hostname = c->value;
	}

	fprintf(stderr, "Too many CNAMEs encountered while querying local hostname\n");
	return NULL;
}

char *
soa_mname(char *host)
{
struct dns_qcache *c;

	while (host && (*host)) {
		if (!(c = query_item('s', host, dns_callback))) return NULL;
		if (c->positive) return c->value;

		/* No? Move closer to the root */
		host = strchr(host, '.');
		if (host) host++;
	}
	return NULL;
}
