#!/usr/bin/env bash
# Remove only this disposable cluster and its explicitly validated credentials.
set -euo pipefail
task_dir=${1:?Supply the TASK_DIR printed by stage4/prepare.sh}
if [[ ! "$task_dir" =~ ^/tmp/sekvyr-stage4\.[[:alnum:]]+$ ]] ||
   [ "$(readlink -f "$task_dir")" != "$task_dir" ] || [ ! -x "$task_dir/kind" ]; then
  printf '%s\n' 'Refusing an unexpected temporary directory.' >&2
  exit 1
fi
sudo -n env DOCKER_HOST=unix:///var/run/docker.sock "$task_dir/kind" delete cluster --name sekvyr-stage4
if [ -n "$(sudo -n docker --host=unix:///var/run/docker.sock ps -a --filter label=io.x-k8s.kind.cluster=sekvyr-stage4 --format '{{.ID}}')" ]; then
  printf '%s\n' 'Isolated cluster containers remain.' >&2
  exit 1
fi
private_dir="$task_dir/private"
if [ -d "$private_dir" ]; then
  if [ -L "$private_dir" ] || [ "$(readlink -f "$private_dir")" != "$task_dir/private" ]; then
    printf '%s\n' 'Refusing an unexpected credential directory.' >&2
    exit 1
  fi
  rm -rf -- "$private_dir"
fi
rm -f -- "$task_dir/kubeconfig"
printf '%s\n' 'Removed only sekvyr-stage4, its private generated test credentials and temporary kubeconfig; images and unrelated data retained.'
