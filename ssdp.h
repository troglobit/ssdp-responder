
#include <syslog.h>

#define BYTES 1024

/* Notify should be less than half the cache timeout */
#define NOTIFY_INTERVAL      600
#define CACHE_TIMEOUT        1800
#define MAX_NUM_IFACES       100
#define MAX_PKT_SIZE         512
#define MC_SSDP_GROUP        "239.255.255.250"
#define MC_SSDP_PORT         1900
#define LOCATION_PORT        MC_SSDP_PORT
#define LOCATION_DESC        "/description.xml"

#define SSDP_ST_ALL          "ssdp:all"

#define logit(lvl, fmt, args...) syslog(lvl, fmt, ##args)

extern int debug;
extern char uuid[];

