#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_http.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define PTCP_WATCH_PORT 80 // HTTP port

// Function to match the HTTP 'User-Agent' header
static bool http_mt(const struct sk_buff *skb, struct xt_action_param *param) {
    const struct xt_http_info *info = (const struct xt_http_info *)param->matchinfo;

    // Log the user_agent string passed from userspace
    printk(KERN_INFO "\nNew Pakcet\nMatching against User-Agent: %s\n", info->user_agent);

    struct iphdr *iph;
    struct tcphdr *tcph;
    u16 sport, dport;
    unsigned char *data;
    unsigned char *tail;
    unsigned int data_len;
    unsigned char *it;
    const unsigned char *user_agent_str = "User-Agent:";
    const unsigned char *ua_input_value = info->user_agent;
    unsigned char *ua_begin = NULL;
    unsigned char *ua_end = NULL;
    int found_match = 0; // Flag for match found
    unsigned int crlf_count = 0;

    if (!skb) return NF_ACCEPT;	// check if return type is valid

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);
    if (sport != PTCP_WATCH_PORT && dport != PTCP_WATCH_PORT) return NF_ACCEPT;

    data = (unsigned char *)tcph + tcph->doff * 4;
    tail = skb_tail_pointer(skb);
    data_len = tail - data;

    if (data_len > 0) {
        printk(KERN_INFO "HTTP Header Start:\n");
        for (it = data; it < tail && crlf_count < 4; ++it) {
            char c = *it;
            // Track "\r\n\r\n" sequence
            if ((c == '\r' && crlf_count % 2 == 0) || (c == '\n' && crlf_count % 2 == 1)) {
                crlf_count++;
            } else if (crlf_count < 4) {
                crlf_count = 0; // Reset if sequence is broken
            }

            if (crlf_count < 4) { // Only log headers before the "\r\n\r\n"
                if (c == '\n') {
                    printk(KERN_CONT "\n");
                } else if (c >= 32 && c <= 126) {
                    printk(KERN_CONT "%c", c);
                }
            }
        }
        printk(KERN_INFO "HTTP Header End\n");

        // Start of user-agent finding logic
        for (it = data; (it + strlen(user_agent_str)) < tail; ++it) {
            if (strncmp(it, user_agent_str, strlen(user_agent_str)) == 0) {
                ua_begin = it;
                break; // Found the User-Agent line
            }
        }

        if (ua_begin) {
            ua_end = memchr(ua_begin, '\n', tail - ua_begin); // Find the end of the line
            for (it = ua_begin; it < ua_end; ++it) {
                if ((it + strlen(ua_input_value)) < ua_end && strncmp(it, ua_input_value, strlen(ua_input_value)) == 0) {
                    found_match = 1; // match found
                    break;
                }
            }

            if (found_match) {
                printk(KERN_INFO "Match Found\n");
                return true;
            }
        }
    }

    // Packet does not contain a match in the User-Agent or the User-Agent is not found, accept it
    printk(KERN_INFO "No Match\n");
    return false; // Return true if matched, false otherwise
}

static int http_mt_check(const struct xt_mtchk_param *par) {
    // Optional: check for correct conditions before a rule is inserted
    return 0;
}

static void http_mt_destroy(const struct xt_mtdtor_param *par) {
    // Optional: cleanup code
}

// Registration structure for our match
static struct xt_match http_mt_reg __read_mostly = {
    .name = "http",
    .revision = 0,
    .family = NFPROTO_UNSPEC, // or NFPROTO_IPV4/NFPROTO_IPV6 if specific
    .match = http_mt,
    .checkentry = http_mt_check,
    .destroy = http_mt_destroy,
    .matchsize = sizeof(struct xt_http_info),
    .me = THIS_MODULE,
};

static int __init http_mt_init(void) {
    printk(KERN_INFO "xt_http module loaded\n");
    return xt_register_match(&http_mt_reg);
}

static void __exit http_mt_exit(void) {
    xt_unregister_match(&http_mt_reg);
    printk(KERN_INFO "xt_http module unloaded\n");
}

MODULE_AUTHOR("Author");
MODULE_DESCRIPTION("Match HTTP traffic by 'User-Agent'");
MODULE_LICENSE("GPL");
module_init(http_mt_init);
module_exit(http_mt_exit);

