#!/bin/sh -ex

test $KUBECONFIG
test -f $KUBECONFIG
go run cmd/kube-mgmt/flag.go cmd/kube-mgmt/main.go --kubeconfig=$KUBECONFIG --log-level=debug --opa-output-bootstrap-bundle=scratch.tar.gz

opa inspect scratch.tar.gz
opa run --disable-telemetry --server \
  --bundle scratch.tar.gz \
  --log-level debug \
  --addr 127.0.0.1:8081 \
  --authorization off \
  --authentication off
