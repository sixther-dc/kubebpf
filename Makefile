ARCH := $(shell uname -m)
ARCH := $(subst x86_64,amd64,$(ARCH))
GOARCH := $(ARCH)

CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

## program

.PHONY: $(PROGRAM)
.PHONY: $(PROGRAM).bpf.c

PROGRAM = main

all:
	$(MAKE) -C . $(PROGRAM)

.PHONY: $(PROGRAM)

$(PROGRAM):
	sh build.sh
	CC=$(CLANG) \
		CGO_ENABLED=1 \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
                GOARCH=$(GOARCH) \
                go build \
                -tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
                -o $(PROGRAM) ./*.go

.PHONE: run
run:
	sudo ./main

.PHONE: cat
cat:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

## clean

.PHONY: clean
clean:
	rm -rf main
	rm -rf $(PROGRAM).bpf.o $(PROGRAM).om