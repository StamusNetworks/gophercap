GIT_VERSION = $(shell git log -1 --pretty=format:"%h")
GO_LDFLAGS = "-X 'gopherCap/cmd.Version=$(GIT_VERSION)'"

all:
	go build -ldflags=$(GO_LDFLAGS) -o ./gopherCap ./
