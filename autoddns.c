#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <pthread.h>
#include <errno.h>
#include "iplist.h"
#include "watchip.h"
#include "dnsquery.h"
#include "dnsupdate.h"

int
main(int argc, char **argv)
{
struct watchip *w;
struct iplist *ipl;
int err = 0;
int c;
int enable4 = 1;
int enable6 = 1;
int detach = 1;
int verbose = 0;
int default_family = 1;
int default_ttl = -1;
int max6_ttl = 86400;
int use_valid = 0;
int pipefd[2];
char *hostname = NULL;
struct watchip_param watchparam;

	memset(&watchparam, 0, sizeof(watchparam));
	watchparam.progname = argv[0];

	while ((c = getopt(argc, argv, "46t:m:Vvh:i:a:d")) != EOF) {
		switch (c) {
			case 'i':
				if ((c = watchip_intf_filter_add(&watchparam, optarg)) > 0) return c;
				break;
			case 'a':
				if ((c = watchip_ip_filter_add(&watchparam, optarg)) > 0) return c;
				break;
			case '4':
				if (default_family) {
					default_family = 0;
					enable6 = 0;
				}
				enable4 = 1;
				break;
			case '6':
				if (default_family) {
					default_family = 0;
					enable4 = 0;
				}
				enable6 = 1;
				break;
			case 't':
				if (isdigit(optarg[0])) {
					default_ttl = atoi(optarg);
				} else {
					err = 1;
				}
				break;
			case 'm':
				if (isdigit(optarg[0])) {
					max6_ttl = atoi(optarg);
				} else {
					err = 1;
				}
				break;
			case 'V':
				use_valid = 1;
				break;
			case 'd':
				detach = 0;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'h':
				hostname = optarg;
				break;
			default:
				err = 1;
				break;
		}
	}
	if (verbose) detach = 0;

	watchparam.enable4 = enable4;
	watchparam.enable6 = enable6;
	if ((c = watchip_filter_finished(&watchparam, verbose)) > 0) return c;

	if (enable4 && (default_ttl == -1)) {
		err = 1;
		fprintf(stderr, "%s: When IPv4 is enabled, a default TTL is required\n"
			"%s: Use either -6 to disable IPv4 or -t to specify DNS TTL\n",
			argv[0], argv[0]);
	}
	if ((!enable6) && use_valid) {
		fprintf(stderr, "%s: warning: -V only makes sense when IPv6 is enabled\n",
			argv[0]);
	}
	if ((!enable4) && (default_ttl != -1)) {
		fprintf(stderr, "%s: warning: -t only makes sense when IPv4 is enabled\n",
			argv[0]);
	}
	if (err || (optind == argc)) {
		fprintf(stderr, "Usage: %s [-4|6] [-v|d] [-V] [-t DNS_ttl] [-m DNS_ttl] [-h hostname] \\\n"
			"          [-i [!]interface[,[!]interface]] [-a [!]ipaddr[,[!]ipaddr]] -- \\\n"
			"          nsupdate command line\n"
			" -4|6: Enable IPv4 or IPv6 (default is both enabled)\n"
			"   -V: Use valid lifetime as DNS TTL instead of prefered lifetime\n"
			"   -v: verbose (implies -d)\n"
			"   -d: do not fork and detach into background\n"
			"   -i: consider only named interfaces (with !, consider all except named)\n"
			"   -a: filter to include/exclude IP addresses\n"
			"   -t: Specify DNS TTL to use for IPv4 addresses\n"
			"   -m: Specify DNS TTL to use for IPv6 addresses with infinite lifetime\n"
			"   -h: Override the local hostname\n"
			"nsupdate comand line is typically \"nsupdate -k keyfile\"\n"
			"Hint: use -d or -v and \"cat\" as the nsupdate command as a simulation mode\n",
			argv[0]
		);
		return 2;
	}

	if (detach) {
		if (pipe(&(pipefd[0])) < 0) {
			fprintf(stderr,
				"%s: pipe() failed while trying go in background: %s\n",
				argv[0], strerror(errno)
			);
			return 1;
		}
		if ((c = fork()) < 0) {
			fprintf(stderr,
				"%s: fork() failed while trying go in background: %s\n",
				argv[0], strerror(errno)
			);
			return 1;
		}
		if (c != 0) {
			char buf[2];
			int n;

			/* parent just waits for the child to be initialized */
			close(pipefd[1]);
			n = read(pipefd[0], buf, 1);
			if (n < 1) {
				waitpid(c, &n, 0);
				if (WIFEXITED(n) && (WEXITSTATUS(n) > 0)) {
					_exit(WEXITSTATUS(n));
				}
				_exit(1);
			}
			_exit(0);
		}
		setsid();
		close(0);
		open("/dev/null", O_RDONLY);
		close(pipefd[0]);
	}

	dnsquery_set_verbose(verbose);

	if (!(ipl = iplist_new(verbose, enable4, enable6))) {
		return 1;
	}

	if (!(w = watchip_start(
		ipl, &watchparam, use_valid, default_ttl, max6_ttl
	))) {
		return 1;
	}

	if (!(dnsupdate_start(ipl, verbose, hostname, argv + optind))) {
		return 1;
	}

	if (detach) {
		char buf[2];

		buf[0] = 0;
		close(1);
		close(2);
		open("/dev/null", O_WRONLY);
		dup(1);
		write(pipefd[1], buf, 1);
		close(pipefd[1]);
	}

	watchip(w);

	return 0;
}
