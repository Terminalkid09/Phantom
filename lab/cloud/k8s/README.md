# Kubernetes / RBAC practice target

A real cluster needs privileged containers, so it is **not** part of
`cloud/docker-compose.yml`. Use a local single-node cluster:

```bash
kind create cluster --name phantom-k8s     # or: k3d cluster create phantom-k8s
kubectl apply -f lab/cloud/k8s/scenario.yaml
```

## What `scenario.yaml` builds

The three findings that make a Kubernetes foothold escalate:

1. **over-permissive ServiceAccount** — `phantom-ci` bound to
   `cluster-admin` (a "just make CI work" shortcut);
2. **a pod that mounts that ServiceAccount** — the entry point after any
   RCE in the workload;
3. **a Secret readable by the ServiceAccount** — the loot
   (`db-credentials`), plus a ConfigMap that looks harmless.

The chain to practise: get code execution in the workload → read the
projected token at
`/var/run/secrets/kubernetes.io/serviceaccount/token` → enumerate what the
token can do (`kubectl auth can-i --list`) → read the Secret → escalate.

Everything in the manifest is a fixture (`lab-only`, fake passwords). Delete
the cluster with `kind delete cluster --name phantom-k8s` when finished.
