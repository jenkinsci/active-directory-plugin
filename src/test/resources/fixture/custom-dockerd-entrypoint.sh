#!/bin/bash
set -ex -o pipefail
DOCKER_OPTS="--config-file=/etc/docker/daemon.json"
$(which dind) dockerd ${DOCKER_OPTS} >/dev/stdout 2>&1 &
sleep 1
mvn -B -Djenkins.test.timeout=1200 "$@"
exit 0