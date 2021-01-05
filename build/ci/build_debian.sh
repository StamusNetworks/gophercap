#!/bin/sh

GO_VERSION=${GO_VERSION:-1.15.6}

GOROOT_BASE=${GOROOT_BASE:-/opt}
GOROOT=$GOROOT_BASE/go
GOPATH=${GOPATH:-/var/go}

apt-get update && apt-get install -y libpcap-dev wget build-essential
wget -O /tmp/golang.tgz https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
tar -xzf /tmp/golang.tgz -C $GOROOT_BASE
mkdir $GOPATH
$GOROOT/bin/go get -u ./
$GOROOT/bin/go build -o ./gopherCap ./
./gopherCap --help
