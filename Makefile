.PHONY: build clean test bench

BINARY=ipfs-key
CMD_DIR=.
LDFLAGS=-s -w
GCFLAGS=-B

build:
	go build -ldflags="$(LDFLAGS)" -gcflags="$(GCFLAGS)" -o ./bin/$(BINARY) main.go

clean:
	rm -rf bin/
	rm -f *.prof *.out *.key
