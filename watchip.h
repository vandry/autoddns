struct filter_list;
struct ip_filter_list;

struct watchip_param {
	/* result out this structure */
	/* then fill this in before the first *_filter_add */
	char *progname;
	/* these will get populated by *_filter_add */
	int intf_filter_sense;	/* -1 -> filter is blacklist, 1 -> filter is whitelist */
	struct filter_list *intf_filter;
	struct ip_filter_list *filter4;
	struct ip_filter_list *filter6;
	/* and then fill these in before watchip_filter_finished */
	int enable4;
	int enable6;
};

struct watchip *watchip_start(
	struct iplist *,
	struct watchip_param *,
	int use_valid,
	int default_ttl,
	int max6_ttl
);

void watchip(struct watchip *);

/* the following functions return 1 for a user error, 2 for malloc failure */

/* add an interface name to the filter */
int watchip_intf_filter_add(struct watchip_param *, char *optarg);

/* add IP address to the filter */
int watchip_ip_filter_add(struct watchip_param *, char *optarg);

/* call when finished building filter */
int watchip_filter_finished(struct watchip_param *, int verbose);
