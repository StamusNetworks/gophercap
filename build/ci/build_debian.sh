#!/bin/sh

GO_VERSION=${GO_VERSION:-1.17}

GOROOT_BASE=${GOROOT_BASE:-/opt}
GOROOT=$GOROOT_BASE/go
GOPATH=${GOPATH:-/var/go}
GOPHERCAP_VERSION=${CI_COMMIT_TAG:-git $CI_COMMIT_SHORT_SHA}

apt-get update && apt-get install -y libpcap-dev wget build-essential
wget -O /tmp/golang.tgz https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
tar -xzf /tmp/golang.tgz -C $GOROOT_BASE
mkdir $GOPATH
$GOROOT/bin/go get -u ./

$GOROOT/bin/go build -ldflags="-X 'gopherCap/cmd.Version=$GOPHERCAP_VERSION'" -o ./gopherCap ./
./gopherCap --help
