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
	docker build -t gopher-builder -f build/Dockerfile.make.bullseye .
	docker run --name gopher-builder -d gopher-builder
	docker cp gopher-builder:/src/gopherCap .
clean-docker-builder:
	docker rm gopher-builder || echo "container not running"
	docker image rm gopher-builder || echo "image not yet built"
