#include <linux/bpf.h>
#include "include/bpf_helpers.h"
// #include <bpf/bpf_helpers.h>
#include "include/bpf_endian.h"
#include "include/types.h"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>


enum package_type {
	T_HTTP = 1,
	T_RPC = 2,
	T_MYSQL = 3,
};

enum package_phase {
	P_REQUEST = 1,
	P_RESPONSE = 2,
};

struct package_t {
	//package的阶段,见 enum package_phase
	__u32 phase;
    __u32 dstip;
    __u32 dstport;
	__u32 srcip;
	__u32 srcport;
	__u32 ack;
	__u32 seq;
	//packge的产生时间
	__u32 duration;
    char req_payload[180];
	char rsp_payload[180];
	__u32 type;
};

//用于接受用户程序传输过来的目标IP
struct bpf_map_def SEC("maps/package_map") filter_map = {
  	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1024 * 16,
};

// 定义了一个名为request_map的map，用于临时记录请求包，以便配对完整的请求/响应包
struct bpf_map_def SEC("maps/package_map") request_map = {
  	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct package_t),
	.max_entries = 1024 * 16,
};

// 定义了一个名为response_map的map，用于传递解析之后的http请求数据到用户态
struct bpf_map_def SEC("maps/package_map") response_map = {
  	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct package_t),
	.max_entries = 1024 * 16,
};

int __is_http_request(char p[12]) {
	//GET
	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
		return 1;
  	}
	//POST
	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
		return 1;
  	}
  	// PUT
  	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
       return 1;
  	}
  	//DELETE
  	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
       return 1;
  	}
  	//HEAD
  	if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
        return 1;
  	}
    //OPTIONS
	// TODO:  fix it.
  	// if ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') && (p[5] == 'N') && (p[6] == 'S')) {
    //     return 1;
  	// }
    //PATCH
  	if ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H')) {
        return 1;
  	}
	return 0;
}

int __is_http_response(char p[12]) {
	//HTTP
	if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
		return 1;
  	}
	return 0;
}

//加载skb中的数据部分到对应的map->payload中
void __load_payload_to_map(struct __sk_buff *skb, __u32 poffset,  char p[180]) {
	unsigned i = 0;
	//低版本内核不允许是要多层级的for循环，经过测试这个数字是12，原因不明。 12 * 15 = 180
	for (; i < 12; i++) {          
        bpf_skb_load_bytes(skb, poffset, &p[i * 15], 15);                                     
       	poffset += 15;                                                                                  
    }
}


//从用户态程序中获取目标IP
int __get_target_ip() {
	__u32 filter_ip_key = 1;
  	__u32 *us_ipAddress;
  	us_ipAddress = bpf_map_lookup_elem(&filter_map, &filter_ip_key);
	if (!us_ipAddress) {
        return 0;
    }
	return *us_ipAddress;
}

// int __handle_requst_package(int typem, struct package_t *p, struct __sk_buff *skb, __u32 poffset) {
// 		struct package_t req = {};
// 		req.srcip = p->srcip;
// 		req.dstip = p->dstip;
// 		req.srcport = p->srcport;
// 		req.dstport = p->dstport;
// 		req.ack = p->ack;
// 		req.seq = p->seq;
// 		req.type = T_HTTP;
// 		req.phase = P_REQUEST;
// 		req.start_time = bpf_ktime_get_ns();
// 		__load_payload_to_map(skb, poffset, req.req_payload);                                   
// 		bpf_map_update_elem(&request_map, &req.ack, &req, BPF_ANY);
// 		return 0;
// }

SEC("socket")
int socket__filter_package(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return -1;

	// Skip non-TCP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_TCP)
		return -1;
	struct package_t p = {};
  	__u32 poffset = 0;
	// __u32 plength = 0;
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
	//tot_len ip包的总总长度， 16位，最大值为 65535 字节
	// __u32 ip_total_length = iph.tot_len;
  	//位运算，相当于 乘以 2 的 2次方，也就是 乘以4， 对应前面的tcp，ip的首部长度字段单位是4字节
  	ip_hlen = ip_hlen << 2;
  	tcp_hlen = tcp_hlen << 2;

	__u32 ip;
	ip = __get_target_ip();
	//过滤掉非目标IP的数据包
	if (iph.saddr != ip && iph.daddr != ip) {
		return -1;
	}

  	//算出tcp携带的数据的其实偏移位置
  	poffset = ETH_HLEN + ip_hlen + tcp_hlen;
  	//算出tcp携带的数据的长度
	// plength = skb->len - poffset;
	char pre_char[12];
	bpf_skb_load_bytes(skb, poffset, pre_char, 12);
    //将tcp包数据部分的迁256个字节放入p，因为http使用的是ascii编码，而ascii编码中一个字符占用一个字节。
	p.srcip = iph.saddr;
	p.dstip = iph.daddr;
	p.srcport = tcph.source;
	p.dstport = tcph.dest;
	p.ack = tcph.ack_seq;
	p.seq = tcph.seq;
	//判断数据包的类型，HTTP,MySQL,MQ,RPC等。
	if (__is_http_request(pre_char)) {
		// __handle_requst_package(T_HTTP, &p, skb, poffset);
		p.type = T_HTTP;
		p.phase = P_REQUEST;
		// bpf_ktime_get_ns 获取内核自启动以来的时长,单位是纳秒,这里获取不到系统当前时间.
		p.duration = bpf_ktime_get_ns();
		__load_payload_to_map(skb, poffset, p.req_payload);                   
		bpf_map_update_elem(&request_map, &p.ack, &p, BPF_ANY);
	} else if (__is_http_response(pre_char)) {
		struct package_t *req;
    	req = bpf_map_lookup_elem(&request_map, &p.seq);
    	if (!req) {
        	return -1;
    	}
		bpf_map_delete_elem(&request_map, &p.seq);
		req->phase = P_RESPONSE;
		req->duration = bpf_ktime_get_ns() - req->duration;
		__load_payload_to_map(skb, poffset, req->rsp_payload);
		bpf_map_update_elem(&response_map, &p.seq, req, BPF_ANY);
	} else {
		return -1;
	}
	// bpf_perf_event_output(skb, &package_map, BPF_F_CURRENT_CPU, &p, sizeof(p));
    return 0;
}
char _license[] SEC("license") = "GPL";
