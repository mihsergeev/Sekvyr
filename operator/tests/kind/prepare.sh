#!/usr/bin/env bash
# Prepare only the isolated local stage-2 test cluster.
set -euo pipefail

readonly cluster=sekvyr-stage2
# Official kind v0.33.0 release images; keep version/image pairs closed.
case "${KUBERNETES_VERSION:-v1.37.0}" in
  v1.37.0) readonly node_image=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5 ;;
  v1.34.11) readonly node_image=kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d ;;
  *) printf '%s\n' 'Unsupported admission-test Kubernetes version' >&2; exit 1 ;;
esac
readonly script_dir=$(cd "$(dirname "$0")" && pwd)
task_dir=$(mktemp -d /tmp/sekvyr-stage2.XXXXXX)
printf 'TASK_DIR=%s\n' "$task_dir"
curl -fsSL --retry 2 https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64 -o "$task_dir/kind"
curl -fsSL --retry 2 https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64.sha256sum -o "$task_dir/kind.sha256sum"
(
  cd "$task_dir"
  sed 's/kind-linux-amd64/kind/' kind.sha256sum | sha256sum -c -
)
chmod 0755 "$task_dir/kind"
"$task_dir/kind" version
if [ -n "$(sudo -n docker --host=unix:///var/run/docker.sock ps -a --filter "label=io.x-k8s.kind.cluster=$cluster" --format '{{.ID}}')" ]; then
  if [ "${1:-}" != "--reuse" ]; then
    printf '%s\n' 'The isolated cluster already exists; refusing to replace it. Use --reuse to export its kubeconfig.' >&2
    exit 1
  fi
  sudo -n env DOCKER_HOST=unix:///var/run/docker.sock "$task_dir/kind" export kubeconfig --name "$cluster" --kubeconfig "$task_dir/kubeconfig"
else
  sudo -n env DOCKER_HOST=unix:///var/run/docker.sock "$task_dir/kind" create cluster --name "$cluster" --image "$node_image" \
    --config "$script_dir/cluster.yaml" --kubeconfig "$task_dir/kubeconfig" --wait 120s --retain
fi
sudo -n chmod 0600 "$task_dir/kubeconfig"
sudo -n chown "$(id -u):$(id -g)" "$task_dir/kubeconfig"
# Use the matching client shipped in the verified node image, not host kubectl.
sudo -n docker --host=unix:///var/run/docker.sock exec "$cluster-control-plane" kubectl version --client=true -o json
printf 'CLUSTER=%s\nKUBECONFIG=%s\n' "$cluster" "$task_dir/kubeconfig"
