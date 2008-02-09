struct filter_list;

struct watchip *watchip_start(
	struct iplist *,
	int enable4,
	int enable6,
	int use_valid,
	int default_ttl,
	int max6_ttl,
	int filter_sense,	/* -1 -> filter is blacklist, 1 -> filter is whitelist */
	struct filter_list  *
);

void watchip(struct watchip *);

int watchip_filter_add(struct filter_list **, char *name);
