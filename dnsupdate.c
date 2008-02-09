#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "iplist.h"
#include "dnsupdate.h"
#include "dnsquery.h"

/* don't submit new work until 2 seconds have passed */
#define NEW_WORK_HOLD_TIME 2
#define RETRY_TIMER_CEILING 300

static int
update_with_list(struct ipl *todo, int verbose, char *override_hostname, char **argv)
{
char *hostname;
char *server;
int hostname_len, n;
int total_len, written, pid;
int pipefd[2];
struct ipl *cur;
char *buf, *p;
char ipbuf[64];

	if (!todo) return 1;

	if (override_hostname) {
		hostname = override_hostname;
	} else {
		if (!(hostname = canonical_hostname())) {
			fprintf(stderr, "DNS update: cannot determine local hostname\n");
			return 0;
		}
	}
	if (!(hostname = strdup(hostname))) {
		fprintf(stderr, "DNS update: strdup failed\n");
		return 0;
	}

	if (!(server = soa_mname(hostname))) {
		fprintf(stderr, "DNS update: cannot find server to which to send update\n");
		free(hostname);
		return 0;
	}
	if (!(server = strdup(server))) {
		fprintf(stderr, "DNS update: strdup failed\n");
		free(hostname);
		return 0;
	}

	hostname_len = strlen(hostname);
		/* "server " + host + " 53\n" + blank line at the end */
	total_len = 7 + strlen(server) + 4 + 1;
	for (cur = todo; cur; cur = cur->next) {
			/* "update delete " + host + " " + ttl + " aaaa (ffff:){7}ffff\n" */
		total_len += 14 + hostname_len + 1 + 12 + 46;
	}

	if (!(buf = malloc(total_len))) {
		fprintf(stderr, "DNS update: malloc failure\n");
		free(hostname);
		free(server);
		return 0;
	}

	sprintf(buf, "server %s 53\n", server);
	p = buf + strlen(buf);

	for (cur = todo; cur; cur = cur->next) {
		if (cur->ttl == -2) {
			sprintf(p, "update delete %s a%s\n", hostname,
				(cur->family == AF_INET6) ? "aaa" : ""
			);
		} else {
			inet_ntop(cur->family, cur->addr, ipbuf, sizeof(ipbuf));
			if (cur->ttl == -1) {
				sprintf(p, "update delete %s a%s %s\n", hostname,
					(cur->family == AF_INET6) ? "aaa" : "",
					ipbuf
				);
			} else {
				sprintf(p, "update add %s %d a%s %s\n", hostname,
					cur->ttl,
					(cur->family == AF_INET6) ? "aaa" : "",
					ipbuf
				);
			}
		}
		p += strlen(p);
	}

	*(p++) = 10;
	total_len = p-buf;

	if (pipe(&(pipefd[0])) < 0) {
		perror("DNS update: pipe");
		free(buf);
		free(hostname);
		free(server);
		return 0;
	}

	if ((pid = fork()) == -1) {
		perror("DNS update: fork");
		close(pipefd[0]);
		close(pipefd[1]);
		free(buf);
		free(hostname);
		free(server);
		return 0;
	}

	if (pid == 0) {
		/* child */
		close(pipefd[1]);
		if (pipefd[0] != 0) {
			dup2(pipefd[0], 0);
			close(pipefd[0]);
		}
		execvp(argv[0], argv);
		fprintf(stderr, "DNS update: exec %s: %s", argv[0], strerror(errno));
		_exit(1);
	}

	close(pipefd[0]);
	written = 0;

	while (written < total_len) {
		if ((n = write(pipefd[1], buf+written, total_len-written)) <= 0) {
			perror("DNS update: pipe write");
			kill(pid, SIGTERM);
			close(pipefd[1]);
			free(buf);
			free(hostname);
			free(server);
			return 0;
		}
		written += n;
	}
	close(pipefd[1]);

	free(buf);
	free(hostname);
	free(server);

	for (;;) {
		waitpid(pid, &n, 0);
		if (WIFEXITED(n)) break;
		kill(pid, SIGCONT);
	}
	if (WEXITSTATUS(n) != 0) {
		fprintf(stderr, "DNS update: child exited with status %d\n", WEXITSTATUS(n));
		return 0;
	}

	return 1;
}

struct dnsupdate_g {
	struct iplist *ipl;
	int verbose;
	char *hostname;
	char **argv;
};

static void *
dnsupdate_run(void *arg)
{
struct iplist *ipl = ((struct dnsupdate_g *)arg)->ipl;
int verbose = ((struct dnsupdate_g *)arg)->verbose;
char *override_hostname = ((struct dnsupdate_g *)arg)->hostname;
char **argv = ((struct dnsupdate_g *)arg)->argv;
struct ipl *work = NULL;
struct ipl *new_work, *cur;
int retry_timeout = 0;
int count = 0;
time_t retrytime;

	free(arg);

	for (;;) {
		new_work = iplist_getwork(
			ipl,
			retrytime,
			retry_timeout ? IPLIST_TIMED : (
				work ? IPLIST_NOHANG : IPLIST_HANG
			)
		);

		if (new_work) {
			for (cur = new_work; cur; cur = cur->next) count++;
		}

		if ((!work) && new_work) {
			sleep(NEW_WORK_HOLD_TIME);
			work = new_work;
			retry_timeout = 0;
			continue;
		}

		if (new_work) {
			for (cur = work; cur && cur->next; cur = cur->next);
			cur->next = new_work;
		}

		if (!work) continue;

		if (verbose) fprintf(stderr, "attempting DDNS update (%d items)\n", count);
		if (update_with_list(work, verbose, override_hostname, argv)) {
			if (verbose) fprintf(stderr, "DDNS update was successful\n");
			while (work) {
				cur = work->next;
				free(work);
				work = cur;
			}
			count = 0;
			retry_timeout = 0;
		} else {
			if (retry_timeout == 0) {
				retry_timeout = 1;
			} else {
				retry_timeout <<= 1;
				if (retry_timeout > RETRY_TIMER_CEILING)
					retry_timeout = RETRY_TIMER_CEILING;
			}
			if (verbose)
				fprintf(
					stderr,
					"DDNS update failed, retry in %d seconds\n",
					retry_timeout
				);
			retrytime = time(NULL) + retry_timeout;

			if (count > ((iplist_count_addresses(ipl) * 3) + 10)) {
				/* The number of updates is getting ridiculous */
				/* flush them and start again */

				if (verbose)
					fprintf(stderr,
						"DDNS update failed and too many pending updates so rebuilding list\n"
					);
				while (work) {
					cur = work->next;
					free(work);
					work = cur;
				}
				count = 0;

				iplist_resubmit(ipl);
			}
		}
	}
}

int
dnsupdate_start(struct iplist *ipl, int verbose, char *hostname, char **argv)
{
pthread_attr_t detached_attr;
pthread_t update_thread;
struct dnsupdate_g *g;

	if (!(g = malloc(sizeof(*g)))) {
		perror("dnsupdate_start: malloc failure");
		return 0;
	}
	g->ipl = ipl;
	g->verbose = verbose;
	g->hostname = hostname;
	g->argv = argv;

	signal(SIGPIPE, SIG_IGN);

	pthread_attr_init(&detached_attr);
	pthread_attr_setdetachstate(&detached_attr, PTHREAD_CREATE_DETACHED);

	pthread_create(&update_thread, &detached_attr, dnsupdate_run, (void *)g);

	return 1;
}
