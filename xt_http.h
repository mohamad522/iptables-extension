#ifndef _XT_HTTP_H
#define _XT_HTTP_H

#include <linux/netfilter.h>

// This structure will be filled with the user-agent string we're looking for.
typedef struct xt_http_info {
    char user_agent[256];
} xt_http_info_t;

#endif /* _XT_HTTP_H */

