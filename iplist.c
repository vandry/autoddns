#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include "iplist.h"

struct iplist {
	struct ipl *old;
	struct ipl *cur;
	int verbose;
	int enable4;
	int enable6;
	int rebuilding;
	int addr_count;
	pthread_mutex_t iplist_mutex;
	pthread_cond_t iplist_cond;
	struct ipl *next_changes;
	struct ipl *changes;
	struct ipl *change_tail;
};

int
iplist_count_addresses(struct iplist *il)
{
int result;

	pthread_mutex_lock(&(il->iplist_mutex));
	result = il->addr_count;
	pthread_mutex_unlock(&(il->iplist_mutex));
	return result;
}

struct ipl *
iplist_getwork(struct iplist *il, time_t end_time, int how)
{
struct ipl *result = NULL;
struct timespec abstime;

	pthread_mutex_lock(&(il->iplist_mutex));
	if (!(il->changes || (how == IPLIST_NOHANG))) {
		if (how == IPLIST_TIMED) {
			abstime.tv_sec = end_time;
			abstime.tv_nsec = 0;
			pthread_cond_timedwait(
				&(il->iplist_cond),
				&(il->iplist_mutex),
				&abstime
			);
		} else {
			pthread_cond_wait(&(il->iplist_cond), &(il->iplist_mutex));
		}
	}
	if (il->changes) {
		result = il->changes;
		il->changes = il->change_tail = NULL;
	}
	pthread_mutex_unlock(&(il->iplist_mutex));
	return result;
}

static struct ipl *
make_deletes(struct iplist *il)
{
struct ipl *delete4 = NULL;
struct ipl *delete6;

	if (il->enable4) {
		if (!(delete4 = malloc(sizeof(*delete4)))) return NULL;
		memset(delete4, 0, sizeof(*delete4));
		delete4->family = AF_INET;
		delete4->ttl = -2;
	}
	if (il->enable6) {
		if (!(delete6 = malloc(sizeof(*delete6)))) {
			if (il->enable4) free(delete4);
			return NULL;
		}
		memset(delete6, 0, sizeof(*delete6));
		delete6->family = AF_INET6;
		delete6->ttl = -2;
		if (il->enable4) {
			delete4->next = delete6;
		} else {
			delete4 = delete6;
		}
	}
	return delete4;
}

struct iplist *
iplist_new(int verbose, int enable4, int enable6)
{
struct iplist *result;

	if (!(result = malloc(sizeof(*result)))) return NULL;
	memset(result, 0, sizeof(*result));

	if (enable4 || enable6) { /* really, this ought to be true! */
		result->enable4 = enable4;
		result->enable6 = enable6;
		if (!(result->next_changes = make_deletes(result))) {
			free(result);
			return NULL;
		}
	}
	result->verbose = verbose;
	pthread_mutex_init(&(result->iplist_mutex), NULL);
	pthread_cond_init(&(result->iplist_cond), NULL);

	return result;
}

/* call with mutex held */
/* this function will steal ownership of "r" */
static void
queue_delete(struct iplist *il, struct ipl *r)
{
char buf[64];

	if (il->verbose) {
		inet_ntop(r->family, r->addr, buf, sizeof(buf));
		fprintf(stderr, "Queue for DDNS: DELETE %s\n", buf);
	}

	r->ttl = -1;
	r->next = NULL;

	if (il->change_tail) {
		il->change_tail->next = r;
		il->change_tail = r;
	} else {
		il->changes = il->change_tail = r;
	}

	return;
}

/* call with mutex held */
/* this function will take a copy of "r" for itself */
static int
queue_update(struct iplist *il, struct ipl *r)
{
char buf[64];
struct ipl *r_copy;

	if (!(r_copy = malloc(sizeof(*r_copy)))) {
		fprintf(stderr, "queue_update: malloc failed\n");
		return 0;
	}
	memcpy(r_copy, r, sizeof(*r_copy));

	r_copy->next = NULL;

	if (il->verbose) {
		inet_ntop(r->family, r->addr, buf, sizeof(buf));
		fprintf(stderr, "Queue for DDNS: ADD %d %s\n", r->ttl, buf);
	}

	if (il->change_tail) {
		il->change_tail->next = r_copy;
		il->change_tail = r_copy;
	} else {
		il->changes = il->change_tail = r_copy;
	}

	return 1;
}

int
iplist_notify(struct iplist *il, int isremove, int ttl, int family, unsigned char *addr)
{
struct ipl **prevp, *cur;
int ok = 1;
char buf[64];

	if (il->verbose) inet_ntop(family, addr, buf, sizeof(buf));

	if (!(il->rebuilding)) pthread_mutex_lock(&(il->iplist_mutex));

	for (prevp = &(il->cur); cur = *prevp; prevp = &(cur->next)) {
		if (family != cur->family) continue;
		if (memcmp(addr, cur->addr, (family == AF_INET) ? 4 : 16)) continue;
		break;
	}

	if (isremove) {
		if (cur) {
			if (il->verbose) fprintf(stderr, "removing address %s\n", buf);
			*prevp = cur->next;
			if (il->rebuilding) {
				free(cur);
			} else {
				queue_delete(il, cur);
			}
			il->addr_count--;
		} else {
			if (il->verbose) fprintf(stderr,
				"request to remove address %s which was not in the list\n",
				buf
			);
		}
	} else {
		if (cur) {
			if (ttl != cur->ttl) {
				if (il->verbose) fprintf(stderr,
					"TTL on %s changed from %d to %d\n",
					buf, cur->ttl, ttl
				);
				cur->ttl = ttl;
				if (!(il->rebuilding)) ok = queue_update(il, cur);
			} else {
				if (il->verbose) fprintf(stderr, "address %s unchanged\n", buf);
			}
		} else {
			if (cur = malloc(sizeof(*cur))) {
				memset(cur, 0, sizeof(*cur));
				cur->next = NULL;
				*prevp = cur;
				cur->family = family;
				cur->ttl = ttl;
				memcpy(cur->addr, addr, (family == AF_INET) ? 4 : 16);
				if (il->verbose) fprintf(stderr, "new address %s TTL %d\n", buf, ttl);
				if (!(il->rebuilding)) ok = queue_update(il, cur);
				il->addr_count++;
			} else {
				fprintf(stderr, "malloc failed for address %s\n", buf);
				ok = 0;
			}
		}
	}

	if (!(il->rebuilding)) {
		if (il->changes) pthread_cond_signal(&(il->iplist_cond));
		pthread_mutex_unlock(&(il->iplist_mutex));
	}

	return ok;
}

void
iplist_rebuild_start(struct iplist *il)
{
struct ipl *tmp;

	if (il->verbose)
		fprintf(stderr, "%sstarting build of address list\n", il->rebuilding ? "re" : ""); 

	if (il->rebuilding) {
		/* was already rebuilding, start over */
		while (il->cur) {
			tmp = il->cur->next;
			free(il->cur);
			il->cur = tmp;
		}
	} else {
		pthread_mutex_lock(&(il->iplist_mutex));
		il->old = il->cur;
		il->cur = NULL;
		il->rebuilding = 1;

		if (il->change_tail) {
			il->change_tail->next = il->next_changes;
		} else {
			il->changes = il->change_tail = il->next_changes;
		}
		while (il->change_tail && (il->change_tail->next))
			il->change_tail = il->change_tail->next;

		il->next_changes = NULL;
	}
}

void
iplist_rebuild_end(struct iplist *il)
{
struct ipl *tmp, *cur, *oldversion;

	if (il->verbose) fprintf(stderr, "finished building address list\n");

	/* Walk the new list */
	il->addr_count = 0;
	for (cur = il->cur; cur; cur = cur->next) {
		il->addr_count++;
		/* Did it exist before? */
		for (oldversion = il->old; oldversion; oldversion = oldversion->next) {
			if (oldversion->family != cur->family) continue;
			if (memcmp(
				oldversion->addr, cur->addr,
				(cur->family == AF_INET) ? 4 : 16
			)) continue;

			if (cur->ttl != oldversion->ttl)
				queue_update(il, cur);

			/* mark it as not new */
			oldversion->ttl = -3;
			break;
		}
		if (!oldversion) {
			/* It's brand new */
			queue_update(il, cur);
		}
	}

	/* Now find old ones that no longer exist
	   destroy the old list at the same time */
	while (il->old) {
		tmp = il->old->next;
		if (il->old->ttl == -3) {
			free(il->old);
		} else {
			queue_delete(il, il->old);
		}
		il->old = tmp;
	}

	if (il->verbose) fprintf(stderr, "finished queueing changes after rebuild of address list\n");

	il->rebuilding = 0;
	if (il->changes) pthread_cond_signal(&(il->iplist_cond));
	pthread_mutex_unlock(&(il->iplist_mutex));
}

void
iplist_resubmit(struct iplist *il)
{
struct ipl *next_changes, *tmp;

	while (!(next_changes = make_deletes(il))) {
		fprintf(stderr, "iplist_resubmit: malloc error, will retry\n");
		sleep(1);
	}

	if (il->next_changes) return;
	if (il->verbose) fprintf(stderr, "resubmitting address list\n");

	pthread_mutex_lock(&(il->iplist_mutex));

	il->old = NULL;
	il->rebuilding = 1;

	/* flush all pending changes */
	while (il->changes) {
		tmp = il->changes->next;
		free(il->changes);
		il->changes = tmp;
	}

	il->changes = il->change_tail = next_changes;
	while (il->change_tail && (il->change_tail->next))
		il->change_tail = il->change_tail->next;

	iplist_rebuild_end(il);
}

