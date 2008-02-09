struct ipl {
	struct ipl *next;
	int family;
	int ttl;	/* -1 means the record should be deleted */
			/* -2 means delete every address */
	unsigned char addr[16];
};

struct iplist *iplist_new(int verbose, int enable4, int enable6);

void iplist_rebuild_start(struct iplist *);
void iplist_rebuild_end(struct iplist *);

int iplist_notify(struct iplist *, int isremove, int ttl, int family, unsigned char *addr);

#define IPLIST_NOHANG 0 /* no blocking */
#define IPLIST_HANG 1 /* no timeout */
#define IPLIST_TIMED 1 /* with timeout */
struct ipl *iplist_getwork(struct iplist *, time_t end_time, int how);

int iplist_count_addresses(struct iplist *);
void iplist_resubmit(struct iplist *);
