#include <linux/icmp.h> // ICMP报文的定义
#include <linux/if_ether.h> // 以太网头部的定义
#include <linux/ip.h> // IP报文的定义
#include <bpf/bpf_endian.h> 
#include <bpf/bpf_helpers.h> // BPF辅助函数

static __always_inline unsigned short is_icmp_ping_request(void *data, void *data_end)
{
    struct ethhdr *eth = (struct ethhdr*)data;
    if(data + sizeof(*eth) > data_end)
        return 0; 

    if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0; // 不是IP协议

    struct iphdr *ip = (struct iphdr*)(data + sizeof(*eth));
    if(data + sizeof(*eth) + sizeof(*ip) > data_end)
        return 0; 

    if(ip->protocol != 0x01) // ICMP协议    or  IPPROTO_ICMP  需要包含 <linux/ip.h>
        return 0; // 不是ICMP协议

    struct icmphdr *icmp = (struct icmphdr*)(data + sizeof(*eth) + sizeof(*ip));
    if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) > data_end)
        return 0; 


    return icmp->type ==  8; // ICMP Echo Request (Ping请求)  书上有
}

static __always_inline void swap_mac_addresses(struct __sk_buff *skb)  // 交换MAC地址  __sk_buff 是BPF的一个结构体，表示网络数据包
{
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source), src_mac, sizeof(src_mac));  // 获取源MAC地址
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, sizeof(dst_mac));  // 获取目标MAC地址
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, sizeof(dst_mac), 0); // 设置源MAC地址为目标MAC地址
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, sizeof(src_mac), 0); // 设置目标MAC地址为源MAC地址

}

#define ICMP_CSUM_OFF \
    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))   // ICMP校验和在数据包中的偏移量 ETH_HLEN是以太网头部长度，sizeof(struct iphdr)是IP头部长度，offsetof(struct icmphdr, checksum)是ICMP头部校验和字段的偏移量  

#define ICMP_TYPE_OFF \
    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))  // ICMP类型 在数据包中的偏移量, 就是 ICMP类型 请求?回复等等

static __always_inline void update_icmp_type(struct __sk_buff *skb, unsigned char old_type, unsigned char new_type)
{
    bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, old_type, new_type, sizeof(new_type)); // 更新ICMP校验和  
    bpf_skb_store_bytes(skb, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0); // 更新ICMP类型
}






