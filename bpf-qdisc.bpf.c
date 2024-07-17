#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>


char _license[] SEC("license") = "GPL";

void bpf_qdisc_skb_drop(struct sk_buff *p, struct bpf_sk_buff_ptr *to_free) __ksym;

SEC("struct_ops/bpf_fifo_enqueue")
int BPF_PROG(bpf_fifo_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	bpf_qdisc_skb_drop(skb, to_free);
	return 1;
}

SEC("struct_ops/bpf_fifo_dequeue")
struct sk_buff *BPF_PROG(bpf_fifo_dequeue, struct Qdisc *sch)
{
	return 0;
}

SEC("struct_ops/bpf_fifo_reset")
void BPF_PROG(bpf_fifo_reset, struct Qdisc *sch)
{
}

SEC(".struct_ops")
struct Qdisc_ops fifo = {
	.enqueue   = (void *)bpf_fifo_enqueue,
	.dequeue   = (void *)bpf_fifo_dequeue,
	.reset     = (void *)bpf_fifo_reset,
	.id        = "bpf_fifo",
};

