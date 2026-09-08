"""Direct tests for the cloud / k8s / mobile capability adapters and
interpreters (phantom.automation.guidance.kit).

These capabilities run through the beacon channel against metadata
services / storage APIs / MDM surfaces — surfaces that cannot exist in a
pure unit environment, so we lock the contract here: the adapters emit
the right commands for the right provider, and the interpreters parse
realistic provider output (IMDSv2 role JSON, sts GetCallerIdentity,
kubelet errors, mdm endpoints) into findings without false positives.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance import kit


def _wm():
    return WorldModel(target="10.0.0.5", target_type="ip")


class TestCloudCredsHarvest(unittest.TestCase):
    """cloud_creds_harvest — IMDS credential capture from the beacon."""

    def setUp(self):
        self.wm = _wm()

    def test_adapter_targets_all_three_providers(self):
        cmd = kit._cloud_creds_adapter(self.wm, {})
        self.assertIn("169.254.169.254/latest/api/token", cmd)       # AWS IMDSv2
        self.assertIn("X-aws-ec2-metadata-token", cmd)
        self.assertIn("metadata.google.internal", cmd)               # GCP
        self.assertIn("Metadata-Flavor: Google", cmd)
        self.assertIn("Metadata: true", cmd)                         # Azure IMDS
        self.assertIn("__CLOUD_START__", cmd)
        self.assertIn("__CLOUD_END__", cmd)

    def test_aws_imdsv2_role_creds_parsed(self):
        out = ("__CLOUD_START__\n"
               "__CLOUD_AWS_ROLE__=my-app-role\n"
               '"AccessKeyId" : "ASIATEST123"\n'
               '"SecretAccessKey" : "SECRETTEST"\n'
               '"Token" : "IQoJb3JpZ2luXQ=="\n'
               "__CLOUD_END__")
        findings = kit._cloud_creds_interp(out, self.wm, {})
        self.assertEqual(len(findings), 2)
        kinds = {f.kind for f in findings}
        self.assertEqual(kinds, {"cloud_creds", "cloud_creds"})
        aws = [f for f in findings if f.key == "iam_aws"]
        self.assertEqual(len(aws), 1)
        self.assertEqual(aws[0].value["provider"], "aws")
        self.assertIn("ASIATEST123", aws[0].value["evidence"])
        self.assertGreaterEqual(aws[0].confidence, 0.9)
        prov = [f for f in findings if f.key == "provider"]
        self.assertEqual(prov[0].value["provider"], "aws")

    def test_aws_role_marker_without_creds_is_not_harvest(self):
        # role detected but the creds fetch returned nothing -> no finding
        out = "__CLOUD_START__\n__CLOUD_AWS_ROLE__=my-app-role\n__CLOUD_END__"
        self.assertEqual(kit._cloud_creds_interp(out, self.wm, {}), [])

    def test_gcp_service_accounts_parsed(self):
        out = ("__CLOUD_START__\n"
               "default/\n"
               "app-engine@project.iam.gserviceaccount.com/\n"
               "__CLOUD_GCP__\n__CLOUD_END__")
        findings = kit._cloud_creds_interp(out, self.wm, {})
        self.assertTrue(any(f.kind == "cloud_creds" and f.key == "iam_gcp"
                            for f in findings))
        prov = [f for f in findings if f.key == "provider"]
        self.assertEqual(prov[0].value["provider"], "gcp")

    def test_azure_identity_parsed(self):
        out = ("__CLOUD_START__\n"
               '{"name": "msiClientId", "value": "00000000-0000-0000-0000-000000000000"}\n'
               "__CLOUD_AZURE__\n__CLOUD_END__")
        findings = kit._cloud_creds_interp(out, self.wm, {})
        self.assertTrue(any(f.kind == "cloud_creds" and f.key == "identity_azure"
                            for f in findings))
        prov = [f for f in findings if f.key == "provider"]
        self.assertEqual(prov[0].value["provider"], "azure")

    def test_no_provider_no_findings(self):
        out = "__CLOUD_START__\nconnection timed out\n__CLOUD_END__"
        self.assertEqual(kit._cloud_creds_interp(out, self.wm, {}), [])


class TestCloudS3Enum(unittest.TestCase):
    """cloud_s3_enum — storage enumeration with harvested IAM creds."""

    def setUp(self):
        self.wm = _wm()

    def test_aws_sts_identity_parsed(self):
        out = ('"GetCallerIdentityResponse": {"GetCallerIdentityResult": '
               '{"Arn": "arn:aws:iam::123456789012:user/svc-enum"}}\n'
               "__CLOUD_S3_OK__")
        findings = kit._cloud_s3_interp(out, self.wm, {"provider": "aws"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "cloud_access")
        self.assertEqual(findings[0].key, "iam_valid")
        self.assertIn("123456789012", findings[0].value["arn"])
        self.assertGreaterEqual(findings[0].confidence, 0.9)

    def test_aws_bucket_listing_parsed(self):
        out = ("2026-01-01 12:00 bucket invoices\n"
               "2026-01-02 13:00 bucket backups\n"
               "__CLOUD_S3_OK__")
        findings = kit._cloud_s3_interp(out, self.wm, {"provider": "aws"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].key, "s3")
        self.assertIn("invoices", findings[0].value["bucket_list"])

    def test_no_buckets_no_finding(self):
        out = "__CLOUD_S3_NONE__"
        self.assertEqual(kit._cloud_s3_interp(out, self.wm,
                                              {"provider": "aws"}), [])

    def test_gcp_gsutil_path(self):
        cmd = kit._cloud_s3_adapter(_wm(), {"provider": "gcp"})
        self.assertIn("gsutil ls", cmd)
        self.assertIn("gcloud auth list", cmd)
        out = ("Credentialed Accounts:\n-> project@developer.gserviceaccount.com\n"
               "gs://ph-data-backup/\n__CLOUD_S3_OK__")
        findings = kit._cloud_s3_interp(out, self.wm, {"provider": "gcp"})
        self.assertTrue(any(f.key == "s3" for f in findings))

    def test_unsupported_provider_never_success(self):
        cmd = kit._cloud_s3_adapter(_wm(), {"provider": "azure"})
        self.assertIn("__CLOUD_S3_NONE__", cmd)
        self.assertEqual(kit._cloud_s3_interp("__CLOUD_S3_NONE__", self.wm,
                                              {"provider": "azure"}), [])


class TestMobileProbe(unittest.TestCase):
    """mobile_probe — MDM / push-gateway / mobile-web surface discovery."""

    def setUp(self):
        self.wm = _wm()

    def test_adapter_uses_mobile_ua_and_mdm_paths(self):
        cmd = kit._mobile_probe_adapter(self.wm, {})
        self.assertIn("iPhone", cmd)
        self.assertIn("/api/v2/mdm", cmd)
        self.assertIn("/enroll", cmd)
        self.assertIn("/v1/push", cmd)
        self.assertIn("__MOBILE_WEB__", cmd)

    def test_endpoint_hits_parsed(self):
        out = ("000:/api/v2/mdm;200:/api/v2/mdm;000:/enroll;301:/enroll;"
               "000:/v1/push;404:/apns")
        findings = kit._mobile_probe_interp(out, self.wm, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "mobile")
        self.assertIn("/api/v2/mdm", findings[0].value["endpoints"])
        self.assertIn("/enroll", findings[0].value["endpoints"])

    def test_home_mobile_web_signal(self):
        findings = kit._mobile_probe_interp("__MOBILE_WEB__", self.wm, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].value["endpoints"], ["home-mobile"])

    def test_no_mobile_surface_no_finding(self):
        out = "000:/api/v2/mdm;404:/enroll;404:/v1/push;404:/apns"
        self.assertEqual(kit._mobile_probe_interp(out, self.wm, {}), [])


class TestK8sEscape(unittest.TestCase):
    """k8s_escape — container-escape primitive probing from a pod."""

    def setUp(self):
        self.wm = _wm()

    def test_adapter_probes_all_escape_primitives(self):
        cmd = kit._k8s_escape_adapter(self.wm, {})
        self.assertIn("serviceaccount/token", cmd)
        self.assertIn("release_agent", cmd)         # privileged cgroup escape
        self.assertIn("/dev/kmsg", cmd)             # host device exposure
        self.assertIn("10250/pods", cmd)            # kubelet API
        self.assertIn("__K8S_START__", cmd)
        self.assertIn("__K8S_END__", cmd)

    def test_sa_token_and_kubelet_parsed(self):
        out = ("__K8S_START__\n"
               "__K8S_SA_TOKEN__\n"
               '"items": [{"metadata": {"name": "api-7c8f9"}}]\n'
               "__K8S_SA_ADMIN__\n"
               "__K8S_KUBELET__\n"
               "__K8S_END__")
        findings = kit._k8s_escape_interp(out, self.wm, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "k8s_escape")
        primitives = findings[0].value["primitives"]
        self.assertIn("sa-list-cluster", primitives)
        self.assertIn("kubelet", primitives)
        self.assertNotIn("privileged-cgroup", primitives)

    def test_privileged_cgroup_and_dev_host_parsed(self):
        out = ("__K8S_START__\n__K8S_SA_TOKEN__\n__K8S_SA_RO__\n"
               "__K8S_PRIV_CGROUP__\n__K8S_DEV_HOST__\n__K8S_END__")
        findings = kit._k8s_escape_interp(out, self.wm, {})
        primitives = findings[0].value["primitives"]
        self.assertIn("privileged-cgroup", primitives)
        self.assertIn("dev-host", primitives)
        self.assertIn("sa-token", primitives)  # token present but list denied
        self.assertNotIn("kubelet", primitives)

    def test_no_primitives_no_finding(self):
        out = "__K8S_START__\n__K8S_END__"
        self.assertEqual(kit._k8s_escape_interp(out, self.wm, {}), [])

    def test_sa_token_only_ro_reported(self):
        # token readable but the API call is denied -> sa-token, not admin
        out = ("__K8S_START__\n__K8S_SA_TOKEN__\n403 Forbidden\n"
               "__K8S_SA_RO__\n__K8S_END__")
        findings = kit._k8s_escape_interp(out, self.wm, {})
        primitives = findings[0].value["primitives"]
        self.assertIn("sa-token", primitives)
        self.assertNotIn("sa-list-cluster", primitives)


class TestCapabilityRegistration(unittest.TestCase):
    """The capabilities exist in the registry with the right category and
    gate wiring (planner effects/effects tests cover chaining)."""

    def setUp(self):
        self.reg = make_registry()

    def test_all_four_registered(self):
        for cid in ("cloud_creds_harvest", "cloud_s3_enum",
                    "mobile_probe", "k8s_escape"):
            cap = self.reg.get(cid)
            self.assertIsNotNone(cap, cid)

    def test_categories_and_effects(self):
        self.assertEqual(self.reg.get("cloud_creds_harvest").category, "post")
        self.assertIn("cloud_creds", self.reg.get("cloud_creds_harvest").effects)
        self.assertEqual(self.reg.get("mobile_probe").category, "recon")
        self.assertIn("mobile", self.reg.get("mobile_probe").effects)
        self.assertIn("k8s_escape", self.reg.get("k8s_escape").effects)
        self.assertIn("cloud_access", self.reg.get("cloud_s3_enum").effects)


if __name__ == "__main__":
    unittest.main()
