PROGS=tc_svc.o
TC_IMG=localhost:5000/tc

progs:	## Build the BPF programs
progs:	$(PROGS)

%.o:	%.c
	clang -g -O2 -Wall -target bpf -c $< -o $@

images:	## Build docker images
images:	$(PROGS)
	docker build --tag fedora-net:36 -f Dockerfile.fedora-net .
	docker build --tag $(TC_IMG) -f Dockerfile.tc .

push:	## Push docker images
	docker push $(TC_IMG)

clean:	## Delete compiled code
	rm -f $(PROGS)

help:	## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: help
.DEFAULT_GOAL := help
