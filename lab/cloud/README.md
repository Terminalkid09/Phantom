# Phantom Cloud Lab — cloud/IAM chain, locally and for free

**Intentionally insecure target for LOCAL, authorized testing only.**

This lab exists so the cloud half of the kill chain can be exercised
end-to-end without an AWS/Azure/GCP account and without spending anything:
enumeration → leaked credentials → instance metadata (SSRF) → `sts:AssumeRole`
→ access to the loot → lateral movement. Everything runs in Docker on your
machine.

## Topology

| Host | Address | What it is |
|---|---|---|
| `localstack` | `172.31.0.10` (+ host `4566`) | AWS APIs: IAM, STS, S3 |
| `imds` | `172.31.0.20` (+ host `1338`) | EC2 instance-metadata mock (the SSRF target) |
| `azurite` | `172.31.0.30` (+ host `10000/10001`) | Azure Blob/Queue stand-in |
| `minio` | `172.31.0.40` (+ host `9000/9001`) | S3-compatible store with a public bucket |

Subnet `172.31.0.0/24` (bridge). Nothing is exposed beyond your host.

## What is deliberately misconfigured

Seeded by `localstack/10-seed.sh` on startup:

1. **`phantom-lab-dev`** — an IAM user with a broad policy:
   `iam:List*`, `iam:Get*`, `s3:ListAllMyBuckets`, `sts:AssumeRole` on `*`.
2. **A long-lived access key** for that user, also committed in the
   bootstrap `user-data` served by the IMDS mock — the classic
   "credentials in user-data" finding, which is exactly what an SSRF to the
   metadata service turns into.
3. **`phantom-lab-admin-role`** — trusts the whole account (`Principal: *`)
   and carries `AdministratorAccess`: the privilege-escalation hop.
4. **`phantom-lab-configs`** / **`phantom-lab-backups`** — buckets holding a
   fake `prod.env` (password + API token), an infra map and a fake DB dump.

The credentials returned by the IMDS mock are **fake** (marked
`_lab_note`) — they cannot authenticate anywhere real.

## Run it

```bash
cd lab/cloud
docker compose up -d            # localstack + imds + azurite + minio
docker compose logs -f localstack | grep phantom-cloud-lab   # seed confirmation
docker compose down             # stop (add -v to wipe the state)
```

Minimal smoke check (host side):

```bash
curl -s http://127.0.0.1:1338/latest/meta-data/iam/security-credentials/
curl -s http://127.0.0.1:1338/latest/meta-data/iam/security-credentials/phantom-lab-ec2-role
curl -s http://127.0.0.1:1338/latest/user-data
```

## Exercise it from Phantom

Point the session at the lab and let the cloud capabilities run against it:

```
use scan            → nmap the 172.31.0.0/24 subnet you reach
use exploit         → cloud/IAM enumeration against localstack (endpoint URL)
use c2              → beacon on a foothold container, then internal recon
```

Give the AWS tooling the lab endpoint rather than real AWS:

```bash
export AWS_ENDPOINT_URL=http://172.31.0.10:4566
export AWS_ACCESS_KEY_ID=<key from the seed output>
export AWS_SECRET_ACCESS_KEY=<secret from the seed output>
export AWS_DEFAULT_REGION=eu-west-1
aws iam list-roles
aws sts assume-role --role-arn arn:aws:iam::000000000000:role/phantom-lab-admin-role \
                    --role-session-name phantom-lateral
aws s3 ls
```

On a foothold inside the subnet, the SSRF/metadata step is just:

```bash
curl -s http://172.31.0.20/latest/meta-data/iam/security-credentials/
```

## Honest limits

- LocalStack implements the **API surface** of AWS, not its security model:
  IAM decisions are simulated. The lab trains the *chain and the parsing*,
  not "would AWS have denied this".
- No AWS Organizations/SCP, no real IMDSv2 enforcement (the mock answers
  both v1 and v2), no VPC endpoint policies.
- Kubernetes is **not** in this compose: a real cluster needs privileged
  containers. For K8s/RBAC practice use `kind` (`kind create cluster`) or
  `k3d`, then run the manifests under `k8s/` (see that README).
- Never publish these ports beyond your host, and never point Phantom at
  `172.31.0.0/24` outside this lab.
