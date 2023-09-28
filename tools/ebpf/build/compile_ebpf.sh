#!/bin/bash
mkdir target
for i in $(ls plugins) 
do 
    clang -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wunused -ggdb -gdwarf -Wall -fpie -Werror -O2 -g -target bpf -c plugins/$i/main.c -o target/$i.bpf.o
done