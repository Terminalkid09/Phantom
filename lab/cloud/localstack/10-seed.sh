#!/bin/sh
# LocalStack ready-hook: seed the misconfigurations Phantom's cloud chain
# is supposed to find. Executed by LocalStack automatically on startup.
#
# Deliberately careless, in the order a real engagement finds them:
#   1. a long-lived access key committed to the bootstrap user-data
#      (see imds/user-data in the lab) — the "leaked key" entry point;
#   2. that key can list roles and read account configuration;
#   3. an over-privileged role trusting the account, assumable with the
#      leaked key (sts:AssumeRole) — privilege escalation;
#   4. a bucket holding "configs" and "backups" that the role can read.
#
# LocalStack's `awslocal` helper is available inside the container.
set -eu

awslocal iam create-user --user-name phantom-lab-dev >/dev/null 2>&1 || true

awslocal iam create-access-key --user-name phantom-lab-dev >/dev/null 2>&1 || true

# A policy that is far too broad for a "developer" user.
cat > /tmp/phantom-dev-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "iam:List*", "Resource": "*"},
    {"Effect": "Allow", "Action": "iam:Get*", "Resource": "*"},
    {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}
  ]
}
JSON
awslocal iam put-user-policy --user-name phantom-lab-dev \
  --policy-name phantom-lab-dev-broad --policy-document file:///tmp/phantom-dev-policy.json \
  >/dev/null 2>&1 || true

# The escalation target: a role that trusts the account and can do anything.
cat > /tmp/phantom-trust.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow",
     "Principal": {"AWS": "*"},
     "Action": "sts:AssumeRole"}
  ]
}
JSON
awslocal iam create-role --role-name phantom-lab-admin-role \
  --assume-role-policy-document file:///tmp/phantom-trust.json >/dev/null 2>&1 || true
awslocal iam attach-role-policy --role-name phantom-lab-admin-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess >/dev/null 2>&1 || true

# The loot: a bucket anyone in this account can read.
awslocal s3 mb s3://phantom-lab-configs >/dev/null 2>&1 || true
printf 'DB_PASSWORD=lab-only-not-a-real-secret\nAPI_TOKEN=lab-fake-token\n' \
  | awslocal s3 cp - s3://phantom-lab-configs/prod.env >/dev/null 2>&1 || true
printf 'internal infrastructure map — lab fixture\n' \
  | awslocal s3 cp - s3://phantom-lab-configs/infra-map.txt >/dev/null 2>&1 || true
awslocal s3 mb s3://phantom-lab-backups >/dev/null 2>&1 || true
printf 'fake dump\n' | awslocal s3 cp - s3://phantom-lab-backups/db.sql >/dev/null 2>&1 || true

echo "[phantom-cloud-lab] seeded: user phantom-lab-dev, role phantom-lab-admin-role, buckets phantom-lab-configs|phantom-lab-backups"
