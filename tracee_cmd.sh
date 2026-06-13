TRACE_OUT="${TRACE_OUT:-/tmp/drsec-tracee-realtime.log}"

docker run \
  --name drsec-tracee-realtime \
  --rm \
  -i \
  --privileged \
  --pid=host \
  --cgroupns=host \
  --network=host \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  aquasec/tracee:0.24.1 \
  --containers enrich=true \
  --containers sockets.docker=/var/run/docker.sock \
  --containers cgroupfs.path=/sys/fs/cgroup \
  --containers cgroupfs.force=true \
  --scope container \
  --scope comm!=tracee \
  --events '*' \
  --output table \
  --output option:parse-arguments \
  > "${TRACE_OUT}" 2>&1 &
