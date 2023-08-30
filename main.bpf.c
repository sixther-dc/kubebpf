#include <linux/bpf.h>
#include "include/bpf_helpers.h"
#include "include/bpf_endian.h"
#include "include/types.h"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>

SEC("socket")
int socket__filter_http_request(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-ICMP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_TCP)
		return 0;

  	__u32 poffset = 0;
	struct iphdr iph;
  	//将skb中的ip头部分按照字节的偏移位置复制到iph变量
  	bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));

  	struct tcphdr tcph;
  	//将tcp的包头复制到tcph变量
  	bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(iph), &tcph, sizeof(tcph));

  	//doff  tcp包的首部偏移， 4位，最大值为15，单位是4字节，也就是说是tcp的头部(包含option)最大是60(15 * 4)字节
  	__u32 tcp_hlen = tcph.doff;
  	//ihl ip包的首部长度， 4位，最大值为15，也就是说是ip的头部(包含option)最大是60(15 * 4)字节
  	__u32 ip_hlen = iph.ihl;

  	//位运算，相当于 乘以 2 的 2次方，也就是 乘以4， 对应前面的tcp，ip的首部长度字段单位是4字节
  	ip_hlen = ip_hlen << 2;
  	tcp_hlen = tcp_hlen << 2;

  	//算出tcp携带的数据的其实偏移位置
  	poffset = ETH_HLEN + ip_hlen + tcp_hlen;
	unsigned long p[12];
    int i = 0;
    //将tcp包数据部分的迁12个字节放入p，因为http使用的是ascii编码，而ascii编码中一个字符占用一个字节。
    for (i = 0; i < 12; i++) {

      p[i] = load_byte(skb, poffset + i);
    }

	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
        goto END;
  	}
  	//POST
  	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
        goto END;
  	}
  	//PUT
  	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
        goto END;
  	}
  	//DELETE
  	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
        goto END;
  	}
  	//HEAD
  	if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
        goto END;
  	}
    //OPTIONS
  	if ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') && (p[5] == 'N') && (p[6] == 'S')) {
        goto END;
  	}
    //PATCH
  	if ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H')) {
        goto END;
  	}
    return 0;
END:
//-1表示放行
return -1;
}


SEC("socket")
int socket__filter_http_response(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-ICMP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_TCP)
		return 0;

  	__u32 poffset = 0;

	struct iphdr iph;
  	//将skb中的ip头部分按照字节的偏移位置复制到iph变量
  	bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph));

  	struct tcphdr tcph;
  	//将tcp的包头复制到tcph变量
  	bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(iph), &tcph, sizeof(tcph));

  	//doff  tcp包的首部偏移， 4位，最大值为15，单位是4字节，也就是说是tcp的头部(包含option)最大是60(15 * 4)字节
  	__u32 tcp_hlen = tcph.doff;
  	//ihl ip包的首部长度， 4位，最大值为15，也就是说是ip的头部(包含option)最大是60(15 * 4)字节
  	__u32 ip_hlen = iph.ihl;

  	//位运算，相当于 乘以 2 的 2次方，也就是 乘以4， 对应前面的tcp，ip的首部长度字段单位是4字节
  	ip_hlen = ip_hlen << 2;
  	tcp_hlen = tcp_hlen << 2;

  	//算出tcp携带的数据的其实偏移位置
  	poffset = ETH_HLEN + ip_hlen + tcp_hlen;
	unsigned long p[12];
    int i = 0;
    //将tcp包数据部分的迁12个字节放入p，因为http使用的是ascii编码，而ascii编码中一个字符占用一个字节。
    for (i = 0; i < 12; i++) {

      p[i] = load_byte(skb, poffset + i);
    }

	if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
		goto END;
	}
    return 0;
END:
//-1表示放行
return -1;
}

char _license[] SEC("license") = "GPL";
