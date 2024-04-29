#include <stdio.h>
#include <xtables.h>
#include <string.h>
#include "xt_http.h"

enum {
    O_USER_AGENT,
};

static const struct xt_option_entry http_opts[] = {
    {.name = "user-agent", .id = O_USER_AGENT, .type = XTTYPE_STRING, .flags = XTOPT_MAND},
    XTOPT_TABLEEND,
};

static void http_help(void) {
    printf("http match options:\n"
           "--user-agent string    Match HTTP 'User-Agent' header\n");
}

// New parse function using xt_option_call
static void http_parse(struct xt_option_call *cb) {
    struct xt_http_info *info = (struct xt_http_info *)cb->data;

    xtables_option_parse(cb);
    switch (cb->entry->id) {
    case O_USER_AGENT:
        strncpy(info->user_agent, cb->arg, sizeof(info->user_agent) - 1);
        info->user_agent[sizeof(info->user_agent) - 1] = '\0'; // Ensure null-termination
        break;
    }
}

static struct xtables_match http_mt_reg = {
    .version       = XTABLES_VERSION,
    .name          = "http",
    .family        = NFPROTO_UNSPEC,
    .size          = XT_ALIGN(sizeof(struct xt_http_info)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_http_info)),
    .help          = http_help,
    .x6_parse      = http_parse,
    .x6_options    = http_opts,
};

void _init(void) {
    xtables_register_match(&http_mt_reg);
}
