GIT_VERSION = $(shell git log -1 --pretty=format:"%h")
GO_LDFLAGS = "-X 'gopherCap/cmd.Version=$(GIT_VERSION)'"

all:
	@$(MAKE)	build
build:
	go build -ldflags=$(GO_LDFLAGS) -o ./gopherCap ./
build-debian:
	@$(MAKE)	clean-docker-builder
	@$(MAKE)	build-docker-debian
	@$(MAKE)	clean-docker-builder
build-docker-debian:
	docker build -t stamus/gophercap .
	docker run --name gophercap-builder --entrypoint bash -d stamus/gophercap
	docker cp gophercap-builder:/usr/local/bin/gopherCap .
clean-docker-builder:
	docker rm gophercap-builder || echo "container not running"
