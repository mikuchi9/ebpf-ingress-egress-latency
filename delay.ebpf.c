#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, __u64);
    __type(value, __u64);
} ingress_timestamp SEC(".maps");


SEC("classifier/ingress")
int ingress_traffic(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    __u64 timestamp = 0;
    __u64 conn_idnt = 0;
    __u16 source_p = 0;
    __u8 protocol;

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *iph = data + sizeof(struct ethhdr);
        
    if ((void *)iph + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    protocol = iph->protocol;
    // the internal delay only for IPV4 packets
    if (protocol == IPPROTO_IPV6)
        return TC_ACT_OK;
        
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct tcphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;
        
        source_p = tcph->source;
    }        
        
    if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(struct udphdr);
        if ((void *)udph + sizeof(struct udphdr) > data_end)
            return TC_ACT_OK;

        source_p = udph->source;
    }
    
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        timestamp = bpf_ktime_get_ns();
        conn_idnt = (iph->saddr << 16) | source_p;
        bpf_map_update_elem(&ingress_timestamp, &conn_idnt, &timestamp, BPF_NOEXIST);
    }

    return TC_ACT_OK;
}

SEC("classifier/egress")
int egress_traffic(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    __u64 conn_idnt = 0;
    __u64 dest_p = 0;
    __u8 err;
    __u64 *timestamp, k_timestamp, delay;
    __u8 protocol;

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *iph = data + sizeof(struct ethhdr);
        
    if ((void *)iph + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    protocol = iph->protocol;
    
    if (protocol == IPPROTO_IPV6)
        return TC_ACT_OK;
        
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct tcphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;
            
        dest_p = tcph->dest;
    }

    if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(struct udphdr);
        if ((void *)udph + sizeof(struct udphdr) > data_end)
            return TC_ACT_OK;
        
        dest_p = udph->dest;
    }
    
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        conn_idnt = (iph->daddr << 16) | dest_p;
        timestamp = (__u64 *)bpf_map_lookup_elem(&ingress_timestamp, &conn_idnt);
        if (timestamp) {
            k_timestamp = bpf_ktime_get_ns();
            delay = k_timestamp - *timestamp;
            bpf_map_delete_elem(&ingress_timestamp, &conn_idnt);
            
            if (protocol == IPPROTO_TCP)
                bpf_printk("TCP , delay is %lu ns\n", delay);
            else 
                bpf_printk("UDP , delay is %lu ns\n", delay);
        }
    }
       
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";