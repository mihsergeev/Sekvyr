# Sekvyr in Kubernetes

[Русская версия](README.ru.md)

Two ways. The first one is preferred: nothing that could be stolen and used
elsewhere is left in the cluster.

## 1. No static secrets: the ServiceAccount token

The pod presents its projected ServiceAccount token, the panel checks the
signature against the cluster keys and returns the values. The token lives an
hour, is bound to the pod and to the panel audience, and is useless anywhere
else.

Once per cluster:

```sh
kubectl get --raw /openid/v1/jwks                                   # cluster keys
kubectl create token default --audience sekvyr | cut -d. -f2 | base64 -d   # look at iss
```

In the panel: Servers, menu "...", "Add a cluster" (name, `issuer`, `audience`,
keys). Then, in the same menu, "Identity in a cluster" with this cluster, the
namespace and the ServiceAccount name, and grant it an environment: the panel
owner does it in the Access section (only the owner sees it), a maintainer with
"Connect an application" on the identity's page under Servers.

Then [agent-sidecar.yaml](agent-sidecar.yaml): an init container writes the file
before the application starts, a sidecar keeps it fresh. The image
`ghcr.io/mihsergeev/sekvyr-agent` holds the same signed agent the panel gives to
servers. It does not update itself in a pod (`--no-update`): change the image
tag instead.

A change reaches the file within a minute, and the application sees it when it
reads the file again. The simplest way is for the application to re-read the
file itself, on a timer or through inotify (the file is replaced as a whole, so
watch the `/secrets` directory, not the file). A reload signal from the sidecar
needs more: the sidecar runs as uid 65534 with every capability dropped and
cannot signal a process of another user. It works with
`shareProcessNamespace: true` on the pod, the same `runAsUser` for the sidecar
and the application, and `--on-change "pkill -HUP -x app"` for the sidecar.
Otherwise restart the pods.

Projects with browser-side encryption need a node key shared by all replicas:
the example shows how to create it once as a Secret and point
`SEKVYR_NODE_KEY` at it. Without a shared key every pod would make its own,
and the project key sealed for one of them would not open in the others.

Why the cluster keys and not TokenReview: the panel needs no credentials for the
cluster and no access to its API. The price is updating the keys when the
cluster rotates them: Servers, the clusters table, "Update keys". The
identities of its pods and their grants stay as they are.

## 2. External Secrets Operator

For those who already run ESO: [external-secrets.yaml](external-secrets.yaml).
The panel answers a plain request, ESO puts the values into a `Secret`.

The price is a static "client id + secret" pair in a cluster `Secret`: ESO makes
a single request and cannot exchange the secret for a short-lived token first.
It is the same kind of secret any other ESO provider keeps, and it travels only
over TLS, but it is exactly what the first way does not need at all.

Every key is a separate request. The audit log records a new set of values, a
new address and once a day; repeated reads in between are counted, not logged
one by one.

## What a machine can do

Only read. The machine API has four routes that change anything (token, report,
revoke, enroll), and none of them touches values. A captured pod gives away its
own secrets, which it holds in memory anyway, but it cannot spoil the shared
store or swap values for its neighbours.
