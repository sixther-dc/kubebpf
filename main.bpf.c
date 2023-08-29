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

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN	14		/* Total octets in header.	 */

unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

SEC("socket")
int socket__filter(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-ICMP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_TCP)
		return 0;

    return -1;
}

char _license[] SEC("license") = "GPL";
