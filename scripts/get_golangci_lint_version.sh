#!/bin/sh

grep -oP '^FROM golangci/golangci-lint:v\d+\.\d+\.\d+' "Dockerfile" | grep -oP 'v\d+\.\d+\.\d+'
