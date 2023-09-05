if [ "`docker images | grep ebpf-devel | wc -l`" -eq 0 ]
then
    docker build -t registry.erda.cloud/erda/ebpf-devel:v0.1 .
fi
if [ "`docker ps | grep erda-ebpf-devel | wc -l`" -eq "0" ]
then
    docker run --name erda-ebpf-devel -d registry.erda.cloud/erda/ebpf-devel:v0.1
fi
docker exec erda-ebpf-devel /bin/bash -c "[ -d /root/bpf_prog ] && rm -rf /root/bpf_prog"
docker cp -a . erda-ebpf-devel:/root/bpf_prog
docker exec erda-ebpf-devel /bin/bash -c "cd /root/bpf_prog/;clang -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wunused -ggdb -gdwarf -Wall -fpie -Werror -O2 -g -target bpf -c main.bpf.c -o main.bpf.o"
docker cp erda-ebpf-devel:/root/bpf_prog/main.bpf.o .
