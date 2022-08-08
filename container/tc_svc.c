#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>

#ifndef __section
# define __section(NAME)                  \
        __attribute__((section(NAME), used))
#endif

#define HANDLE_NODEPORT true

struct bpf_ct_opts___local {
        int netns_id;
        int error;
        __u8 l4proto;
        __u8 dir;
        __u8 reserved[2];
} __attribute__((preserve_access_index));

struct nf_conn {
        unsigned long status;
} __attribute__((preserve_access_index));

// struct nf_conn;

struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *, struct bpf_sock_tuple *, __u32,
                                  struct bpf_ct_opts___local *, __u32) __ksym;
void bpf_ct_release(struct nf_conn *) __ksym;


#ifndef __maybe_unused
#define __maybe_unused   \
        __attribute__((unused))
#endif


SEC("tc")
int tc_main(struct __sk_buff *skb)
{
    struct bpf_sock_tuple    bpf_tuple;

    struct bpf_ct_opts___local opts_def = { .l4proto = IPPROTO_TCP, .netns_id = -1 };
    struct nf_conn *ct = NULL;

    __builtin_memset(&bpf_tuple, 0, sizeof(bpf_tuple.ipv4));

    char hello_str[] = "hello tc pkt";
    char ct_str_good[] = "CT lookup success! CT entry status %x ";
    char ct_str_fail[] = "CT lookup fail! ";

    bpf_trace_printk(hello_str, sizeof(hello_str));

    const int l3_off = ETH_HLEN;                      // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset
    const int tcp_end = l4_off + sizeof(struct tcphdr);

    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    if (data_end < data + l4_off)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
       return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcph = (struct tcphdr *)(ip + 1);

    if (data_end < data + tcp_end)
        return TC_ACT_OK;

    bpf_tuple.ipv4.saddr = ip->saddr;
    bpf_tuple.ipv4.daddr = ip->daddr;

    bpf_tuple.ipv4.sport = tcph->source;
    bpf_tuple.ipv4.dport = tcph->dest;

    opts_def.l4proto = IPPROTO_TCP;
    opts_def.netns_id = -1;

    ct = bpf_skb_ct_lookup(skb, &bpf_tuple, sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def));

    if (ct) {
        bpf_trace_printk(ct_str_good, sizeof(ct_str_good));
        bpf_ct_release(ct);

    } else {
        bpf_trace_printk(ct_str_fail, sizeof(ct_str_fail));
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
