FROM ubuntu:18.04

RUN apt update && apt -y install build-essential git make libelf-dev clang strace tar bpfcc-tools gcc-multilib
CMD ["sleep","infinity"]