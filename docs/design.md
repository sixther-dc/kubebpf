## 框架选型
我们知道 ebpf 代码分为用户态跟内核态，内核态没有什么好说的，老老实实写内核c就好，用户态的框架目前社区有太多，github上可以找出几十种，bcc，cilium， libbpfgo等等，由于我想使用go来构建用户态的代码，所以能选的也就不多了，主要是在cilium跟libbpfgp中做选择。

两者在使用层面没有太多的不同，照着它们的 api 去写就好，最初我是使用libbpfgo，但是当我将编译好的代码在其他机器上运行的时候，会由于没有btf而失败，因为libbpfgo依赖了libbpf库，而libbpf依赖了btf，所以最后测试了下cilium，可以在没有开启btf的机器上正常运行。
## 如何根据tcp流还原出一次http请求
用户态的框架确定好了之后，就可以开始编写代码了。

由于我们的目的是在 kubernetes 环境下通过 ebpf 来抓取每个 pod 的 http 请求数据，并根据这些 http 请求数据来计算出对应 pod 的 R.E.D指标。

抓包，使用 sec("socket") 来对经过网卡的数据包进行抓取，并且过滤出TCP协议的数据包，代码实例如下。
```  c
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
```
由于 HTTP 是文本协议，我们可以将 TCP 包的 Payload 文本化后，通过判断里面的字符串数据来确定一个包是 http request 还是 response。

那如何将 reqeust 跟 reponse 还原为一次完整的http请求呢，经过抓包，我们可以看到 reqeust 包的 ack number 跟 response 包的 seq number 是一样的，见下图。
![Dashboard](./assets/http_package.png)
这样，我们就可以通过一个hashmap， 以ack number为key来匹配对应seq number 的 response 包，进而来还原出一次完整的http请求。
## map的介绍
ebpf 通过 map 来跟用户态程序交互，可以将 ebpf 采集到的数据通过map来传输到用户态，也可以在用户态通过map来写入数据，进而影响 ebpf 程序的行为。

对于一般的指标，使用ringbuf是最合适的，ringbuf 是一个FIFO的队列，用于流式的将内核中的数据传送到用户态，类似生产者，消费者的场景。ebpf 不断向ringbuf中写入数据，然后用户态来获取。但是我们可以在 bcc 的 [文档](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) 中看到 ringbuf 是在5.8的内核版本中才引入的，所以兼容性较低。

另外一个FIFO的map是BPF_MAP_TYPE_PERF_EVENT_ARRAY，在4.3内核中引用，但是BPF_MAP_TYPE_PERF_EVENT_ARRAY依赖的 bpf_perf_event_output 方法只有在高版本内核中才能在[sec("socket")]上下文中使用([参考](https://stackoverflow.com/questions/59624275/can-ebpfs-perf-submit-be-used-in-a-socket-filter-program-as-well))。

因此，最终我们使用了最早被引入的 Hash Map，其最低可以支持3.19内核，Hash Map 一般用于有固定对象的场景，比如一个固定进程的对象，要获取到它的cpu信息，ebpf 不断的去修改该 pid 对应的 cpu 信息，然后用户态在该map中来获取cpu的实时值。

但是用Hash Map来传输这种流式的指标就需要我们在用户态去遍历并且获取到后就将其删除，防止Map满了导致内核态ebpf程序无法写入的问题，这里算是一个hack。

## 如何关联k8s元数据
解决了使用ebpf从tcp流中还原出http请求以及将数据吐给用户态后，接下来我们需要看一下如何将这些请求跟k8s的pod关联起来。

最好的办法是是能确定每一个数据包都由哪个进程发出的或者要发送给哪个进程，但是由于sec("socket")抓取出来的数据包中不会携带任何的进程信息，就需要其他办法，deeflow 开源了一个[内核模块](https://github.com/deepflowio/tcp-option-tracing/blob/main/module/tot.c)，用于在发出数据包的时候，将pid写入tcp包头的OPTION字段，然后就可以通过在数据包中提取 pid 来跟进程关联，进而关联k8s的pod。

考虑到这种方式要安装额外的内核模块或者ebpf程序，所以最终我们选择了其他方案，利用k8s的watch机制，来watch endpoints资源，endpints资源中包含了 pod 的 ip 以及端口，可以通过pod在宿主机上的网卡来给每一个pod创建一个独立的ebpf程序，那么该ebpf程序所抓取的数据包就一定属于该pod，从而实现了数据包跟k8s元数据的关联。

但是有一个特例，就是hostnetwork类型的pod，由于他们都共用了宿主机的网卡，所有这个时候还需要再通过端口来区分一下，这也是从endpints来出发解决关联k8s元数据的原因之一。
## 插件化架构
agent目前通过ebpf采集了http数据，我们希望还可以采集更多的数据，所以设计了插件化的架构，这里参考了telegraf，在agent启动的时候启动注册的所有插件，然后所有的插件将采集的数据写入到一个channel中，最终消费这个channel将数据发送到外部服务或者存储中。
## 写入数据到influxdb
agent默认提供了influxdb的数据写入，直接调用它的api即可，值得注意的一点是，由于数据量比较大，如果每个指标数据都要写入一次influxdb的话，那每写一次都要再在influxdb的pod上有一条http流量，而这个http流量又会被ebpf抓取形成一次指标写入，最终这样的循环会很快将influxdb的存储打满。

所以在写入influxdb我们采用了定时分批写入，每个指标先只是放入到内存中，然后每隔一段时间再将内存中的这些指标数据一次性的写入到influxdb中，对这段内存数据的读取以及写入形成了一个临界区，所以通过加锁来解决读写过程中的数据一致性问题。
## grafana可视化展示
kubebpf使用grafana作为展示层，为了实现一键安装，无需配置的效果，这里使用了provisioning 的方式来配置 datasource 跟 dashboard。