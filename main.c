#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/moduleparam.h>

#define IPADDRESS(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

#define DNS_PORT 53

bool drop_in = true;
module_param(drop_in, bool, S_IRUGO | S_IWUSR);

bool drop_out = true;
module_param(drop_out, bool, S_IRUGO | S_IWUSR);

bool drop_udp = false;
MODULE_PARM_DESC(drop_udp, "Drop UDP");

bool drop_dns = false;
MODULE_PARM_DESC(drop_udp, "Don't drop DNS packets");


bool drop_tcp = false;
MODULE_PARM_DESC(drop_tcp, "Drop TCP");

bool drop_icmp = false;
MODULE_PARM_DESC(drop_icmp, "Drop ICMP");



//struct kernel_param_ops
//{
// int (*set)(const char *val, const struct kernel_param *kp);
// int (*get)(char *buffer, const struct kernel_param *kp);
// void (*free)(void *arg);
//};

// ================================================================================
//  UDP
// ================================================================================
static int set_udp(const char *val, const struct kernel_param *kp) {
    int res = param_set_bool(val, kp);
    if (res != 0) {
        return -1;
    }
    printk(KERN_INFO "oscw: New value of drop_udp = %d\n", drop_udp);
    return 0;
}
static struct kernel_param_ops param_ops_udp = {
        .set = set_udp,
        .get = param_get_bool,
};
module_param_cb(drop_udp, &param_ops_udp, &drop_udp, S_IRUGO | S_IWUSR);
// ================================================================================


// ================================================================================
//  DNS
// ================================================================================
static int set_dns(const char *val, const struct kernel_param *kp) {
    int res = param_set_bool(val, kp);
    if (res != 0) {
        return -1;
    }
    printk(KERN_INFO "oscw: New value of drop_dns = %d\n", drop_dns);
    return 0;
}
static struct kernel_param_ops param_ops_dns = {
        .set = set_dns,
        .get = param_get_bool,
};
module_param_cb(drop_dns, &param_ops_dns, &drop_dns, S_IRUGO | S_IWUSR);
// ================================================================================


// ================================================================================
//  TCP
// ================================================================================
static int set_tcp(const char *val, const struct kernel_param *kp) {
    int res = param_set_bool(val, kp);
    if (res != 0) {
        return -1;
    }
    printk(KERN_INFO "oscw: New value of drop_tcp = %d\n", drop_tcp);
    return 0;
}

static struct kernel_param_ops param_ops_tcp = {
        .set = set_tcp,
        .get = param_get_bool,
};
module_param_cb(drop_tcp, &param_ops_tcp, &drop_tcp, S_IRUGO | S_IWUSR);
// ================================================================================


// ================================================================================
//  ICMP
// ================================================================================
static int set_icmp(const char *val, const struct kernel_param *kp) {
    int res = param_set_bool(val, kp);
    if (res != 0) {
        return -1;
    }
    printk(KERN_INFO "oscw: New value of drop_icmp = %d\n", drop_icmp);
    return 0;
}

static struct kernel_param_ops param_ops_icmp = {
        .set = set_icmp,
        .get = param_get_bool,
};
module_param_cb(drop_icmp, &param_ops_icmp, &drop_icmp, S_IRUGO | S_IWUSR);
// ================================================================================


static struct nf_hook_ops *nf_block_ingoing_ops = NULL;
static struct nf_hook_ops *nf_block_outgoing_ops = NULL;

static unsigned int blocker_input(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if (!skb) return NF_ACCEPT;

    struct iphdr *ip_header = ip_hdr(skb);
    struct udphdr *udp_header = NULL;
    struct tcphdr *tcp_header = NULL;
    int portsrc = 0, portdst = 0;


    u32 saddr, daddr;
    saddr = ntohl(ip_header->saddr);
    char *src_ipaddr = (char *)kmalloc(16, GFP_KERNEL);
    sprintf(src_ipaddr, "%u.%u.%u.%u", IPADDRESS(saddr));

    daddr = ntohl(ip_header->daddr);
    char *dst_ipaddr = (char *)kmalloc(16, GFP_KERNEL);
    sprintf(dst_ipaddr, "%u.%u.%u.%u", IPADDRESS(daddr));

    switch (ip_header->protocol) {
        case IPPROTO_UDP:
            udp_header = udp_hdr(skb);
            portsrc = ntohs(udp_header->source);
            portdst = ntohs(udp_header->dest);
            if (portdst == DNS_PORT || portsrc == DNS_PORT) {
                printk(KERN_INFO "os: [UDP-DNS] %s:%d <- %s:%d", dst_ipaddr, portdst, src_ipaddr, portsrc);
                if (drop_dns) {
                    printk(KERN_CONT " --- DROP\n");
                    return NF_DROP;
                }
                printk(KERN_CONT " --- ACCEPT\n");
                return NF_ACCEPT;
            }

            printk(KERN_INFO "os: [UDP] %s:%d <- %s:%d", dst_ipaddr, portdst, src_ipaddr, portsrc);
            if (drop_udp) {
                printk(KERN_CONT " --- DROP\n");
                return NF_DROP;
            }
            printk(KERN_CONT " --- ACCEPT\n");
            return NF_ACCEPT;

        case IPPROTO_TCP:
            tcp_header = tcp_hdr(skb);
            portsrc = ntohs(tcp_header->source);
            portdst = ntohs(tcp_header->dest);
            printk(KERN_INFO "os: [TCP] %s:%d <- %s:%d", dst_ipaddr, portdst, src_ipaddr, portsrc);
            if (drop_tcp) {
                printk(KERN_CONT " --- DROP\n");
                return NF_DROP;
            }
            printk(KERN_CONT " --- ACCEPT\n");
            return NF_ACCEPT;

        case IPPROTO_ICMP:
            printk(KERN_INFO "os: [ICMP] <-");

            if (drop_icmp) {
                printk(KERN_CONT " --- DROP\n");
                return NF_DROP;
            }
            printk(KERN_CONT " --- ACCEPT\n");
            return NF_ACCEPT;
    }

    printk(KERN_INFO "os:.....DEFAULT.....\n");
    return NF_ACCEPT;
}


static unsigned int blocker_output(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if (!skb) return NF_ACCEPT;

    struct iphdr *ip_header = ip_hdr(skb);
    struct udphdr *udp_header = NULL;
    struct tcphdr *tcp_header = NULL;
    int portsrc = 0, portdst = 0;


    u32 saddr, daddr;
    saddr = ntohl(ip_header->saddr);
    char *src_ipaddr = (char *)kmalloc(16, GFP_KERNEL);
    sprintf(src_ipaddr, "%u.%u.%u.%u", IPADDRESS(saddr));

    daddr = ntohl(ip_header->daddr);
    char *dst_ipaddr = (char *)kmalloc(16, GFP_KERNEL);
    sprintf(dst_ipaddr, "%u.%u.%u.%u", IPADDRESS(daddr));

    switch (ip_header->protocol) {
        case IPPROTO_UDP:
            udp_header = udp_hdr(skb);
            portsrc = ntohs(udp_header->source);
            portdst = ntohs(udp_header->dest);
            if (portdst == DNS_PORT || portsrc == DNS_PORT) {
                printk(KERN_INFO "os: [UDP-DNS] %s:%d -> %s:%d", src_ipaddr, portsrc, dst_ipaddr, portdst);
                if (drop_dns) {
                    printk(KERN_CONT " --- DROP\n");
                    return NF_DROP;
                }
                printk(KERN_CONT " --- ACCEPT\n");
                return NF_ACCEPT;
            }

            printk(KERN_INFO "os: [UDP] %s:%d -> %s:%d", src_ipaddr, portsrc, dst_ipaddr, portdst);
            if (drop_udp) {
                printk(KERN_CONT " --- DROP\n");
                return NF_DROP;
            }
            printk(KERN_CONT " --- ACCEPT\n");
            return NF_ACCEPT;

        case IPPROTO_TCP:
            tcp_header = tcp_hdr(skb);
            portsrc = ntohs(tcp_header->source);
            portdst = ntohs(tcp_header->dest);
            printk(KERN_INFO "os: [TCP] %s:%d -> %s:%d", src_ipaddr, portsrc, dst_ipaddr, portdst);
            if (drop_tcp) {
                printk(KERN_CONT " --- DROP\n");
                return NF_DROP;
            }
            printk(KERN_CONT " --- ACCEPT\n");
            return NF_ACCEPT;

        case IPPROTO_ICMP:
            printk(KERN_INFO "os: [ICMP] ->");

            if (drop_icmp) {
                printk(KERN_CONT " --- DROP\n");
                return NF_DROP;
            }
            printk(KERN_CONT " --- ACCEPT\n");
            return NF_ACCEPT;
    }

    printk(KERN_INFO "os:.....DEFAULT.....\n");
    return NF_ACCEPT;
}


static int __init nf_minifirewall_init(void) {
    printk(KERN_INFO "oscw: Loading ...\n");
// struct nf_hook_ops {
//     struct list_head list;
//     nf_hookfn *hook; // User fills in from here down.
//     int pf;
//     int priority; // Hooks are ordered in ascending priority.
//     int hooknum;
                    //  NF_INET_PRE_ROUTING
                    //      – после получения пакета на сетевую карту
                    //      – до принятия решения о маршрутизации
                    //  NF_INET_LOCAL_IN
                    //      - для сетевых пакетов, предназначенных для текущего узла.
                    //  NF_INET_FORWARD
                    //      - для сетевых пакетов, которые должны быть перенаправленыю
                    //  NF_INET_POST_ROUTING
                    //      - для сетевых пакетов, прошедших роутинг и перед отправкой на сетевую карту
                    //  NF_INET_LOCAL_OUT
                    //      - для сетевых пакетов, генерируемых процессами на текущем хосте.
// };

    if (drop_in){
        nf_block_ingoing_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
        if (nf_block_ingoing_ops != NULL) {
            nf_block_ingoing_ops->hook = (nf_hookfn *)blocker_input;
            nf_block_ingoing_ops->hooknum = NF_INET_PRE_ROUTING;
            nf_block_ingoing_ops->pf = NFPROTO_IPV4;
            nf_block_ingoing_ops->priority = NF_IP_PRI_FIRST; // set the priority
    //  nf_register_hook - для регистрации нашей hook-функции
            nf_register_net_hook(&init_net, nf_block_ingoing_ops);
        }
        printk(KERN_INFO "oscw: Ingoing packets will be dropped\n");
    }

    if (drop_out) {
        nf_block_outgoing_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
        if (nf_block_outgoing_ops != NULL) {
            nf_block_outgoing_ops->hook = (nf_hookfn *)blocker_output;
            nf_block_outgoing_ops->hooknum = NF_INET_LOCAL_OUT;
            nf_block_outgoing_ops->pf = NFPROTO_IPV4;
            nf_block_outgoing_ops->priority = NF_IP_PRI_FIRST; // set the priority
            //  nf_register_hook - для регистрации нашей hook-функции
            nf_register_net_hook(&init_net, nf_block_outgoing_ops);
        }
        printk(KERN_INFO "oscw: Outoing packets will be dropped\n");
    }
    return 0;
}

static void __exit nf_minifirewall_exit(void) {
    printk(KERN_INFO "oscw: Exiting...");
    if (nf_block_ingoing_ops != NULL) {
//  nf_unregister_hook - для удаление нашей функции из цепочки.
        nf_unregister_net_hook(&init_net, nf_block_ingoing_ops);
        kfree(nf_block_ingoing_ops);
    }
    if (nf_block_outgoing_ops != NULL) {
//  nf_unregister_hook - для удаление нашей функции из цепочки.
        nf_unregister_net_hook(&init_net, nf_block_outgoing_ops);
        kfree(nf_block_outgoing_ops);
    }
}

module_init(nf_minifirewall_init);
module_exit(nf_minifirewall_exit);
MODULE_LICENSE("GPL");