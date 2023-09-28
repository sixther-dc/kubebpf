#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ "`docker images | grep ebpf-devel | wc -l`" -eq 0 ]
then
    docker build -t registry.erda.cloud/erda/ebpf-devel:v0.1 .
fi
if [ "`docker ps | grep erda-ebpf-devel | wc -l`" -eq "0" ]
then
    docker run --name erda-ebpf-devel -d registry.erda.cloud/erda/ebpf-devel:v0.1
fi
docker exec erda-ebpf-devel /bin/bash -c "[ -d /root/bpf_prog ] && rm -rf /root/bpf_prog"
docker cp -a ../../../ebpf erda-ebpf-devel:/root/bpf_prog/
docker cp -a compile_ebpf.sh  erda-ebpf-devel:/root/bpf_prog/
docker exec erda-ebpf-devel /bin/bash -c "cd /root/bpf_prog/; sh -x compile_ebpf.sh"
docker cp erda-ebpf-devel:/root/bpf_prog/target ../../../
