#!/usr/bin/env bash
# Remove only this test cluster and its temporary local admin kubeconfig.
set -euo pipefail
task_dir=${1:?Supply the TASK_DIR reported by prepare.sh}
if [[ ! "$task_dir" =~ ^/tmp/sekvyr-stage2\.[[:alnum:]]+$ ]] ||
   [ "$(readlink -f "$task_dir")" != "$task_dir" ] || [ ! -x "$task_dir/kind" ]; then
  printf '%s\n' 'Refusing an unexpected temporary directory.' >&2
  exit 1
fi
sudo -n env DOCKER_HOST=unix:///var/run/docker.sock "$task_dir/kind" delete cluster --name sekvyr-stage2
if [ -n "$(sudo -n docker --host=unix:///var/run/docker.sock ps -a --filter label=io.x-k8s.kind.cluster=sekvyr-stage2 --format '{{.ID}}')" ]; then
  printf '%s\n' 'Test cluster containers remain.' >&2
  exit 1
fi
rm -f -- "$task_dir/kubeconfig"
printf '%s\n' 'Removed sekvyr-stage2 and its temporary kubeconfig; images and unrelated containers retained.'
