#!/bin/bash

CGO_ENABLED=0 GOOS=linux go build -o terraform-provider-vtm_v5.2.0 -a -ldflags '-extldflags "-static"' .
