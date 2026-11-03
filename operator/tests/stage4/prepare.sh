#!/usr/bin/env bash
# Prepare only the named isolated stage-4 cluster, never a current kube context.
set -euo pipefail
readonly cluster=sekvyr-stage4
readonly node_image=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
readonly script_dir=$(cd "$(dirname "$0")" && pwd)
task_dir=$(mktemp -d /tmp/sekvyr-stage4.XXXXXX)
chmod 0700 "$task_dir"
printf 'TASK_DIR=%s\n' "$task_dir"
curl -fsSL --retry 2 https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64 -o "$task_dir/kind"
curl -fsSL --retry 2 https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64.sha256sum -o "$task_dir/kind.sha256sum"
(
  cd "$task_dir"
  sed 's/kind-linux-amd64/kind/' kind.sha256sum | sha256sum -c -
)
chmod 0755 "$task_dir/kind"
if [ -n "$(sudo -n docker --host=unix:///var/run/docker.sock ps -a --filter "label=io.x-k8s.kind.cluster=$cluster" --format '{{.ID}}')" ]; then
  if [ "${1:-}" != "--reuse" ]; then
    printf '%s\n' 'The isolated stage-4 cluster already exists; refusing to replace it.' >&2
    exit 1
  fi
  sudo -n env DOCKER_HOST=unix:///var/run/docker.sock "$task_dir/kind" export kubeconfig --name "$cluster" --kubeconfig "$task_dir/kubeconfig"
else
  sudo -n env DOCKER_HOST=unix:///var/run/docker.sock "$task_dir/kind" create cluster --name "$cluster" --image "$node_image" \
    --config "$script_dir/cluster.yaml" --kubeconfig "$task_dir/kubeconfig" --wait 180s --retain
fi
sudo -n chmod 0600 "$task_dir/kubeconfig"
sudo -n chown "$(id -u):$(id -g)" "$task_dir/kubeconfig"
sudo -n docker --host=unix:///var/run/docker.sock exec "$cluster-control-plane" kubectl version -o json
printf 'CLUSTER=%s\nKUBECONFIG=%s\n' "$cluster" "$task_dir/kubeconfig"
