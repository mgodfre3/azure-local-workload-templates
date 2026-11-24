import copy
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
# The target provides cloud-init's real schemas. These focused unit cases supply
# the schema boundary without installing cloud-init on the deployment workstation.
spec = importlib.util.spec_from_file_location(
    "policy", pathlib.Path(__file__).parents[1] / "guest" / "validate-cloud-init.py"
)
policy = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"cloudinit": types.ModuleType("cloudinit"),
                            "cloudinit.config": types.SimpleNamespace(schema=None)}):
    spec.loader.exec_module(policy)

CLOUD_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "write_files": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "properties": {**{k: {"type": "string"} for k in ("path", "owner", "content", "permissions")},
                           "encoding": {"enum": ["text/plain", "b64"]}},
        }},
        "runcmd": {"type": "array"},
    },
}
NETWORK_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {"version": {"enum": [1]}, "config": {"type": "array", "items": {
        "type": "object", "properties": {
            "name": {"type": "string"}, "subnets": {"type": "array", "items": {
                "type": "object", "additionalProperties": False,
                "properties": {"type": {"enum": ["static"]}, "address": {"type": "string"}},
            }},
        },
    }}},
}


class ProvisioningPolicyTests(unittest.TestCase):
    def setUp(self):
        self.data = {"write_files": [{"path": policy.AGENT_SCRIPT, "owner": "root:root",
                                     "content": "echo fixture\n", "permission": "0744", "encoding": "raw"}],
                     "runcmd": [["bash", policy.AGENT_SCRIPT]]}
        self.status = {"v1": {name: {"errors": [], "finished": 1.0, "recoverable_errors": {}}
                              for name in policy.PHASES}}
        self.status["v1"]["init"]["recoverable_errors"] = {"WARNING": sorted(policy.WARNINGS)}
        self.result = {"v1": {"errors": []}}
        self.network = {"version": 1, "config": [{"name": "eth0", "subnets": [
            {"type": "static", "address": "192.0.2.10", "_orig_eni_name": "eth0"}]}]}

    def assess(self):
        return policy.assess(self.data, self.status, self.result, self.network, CLOUD_SCHEMA, NETWORK_SCHEMA)

    def test_exact_known_warnings_are_evidence_not_clean_schema_and_inputs_are_unchanged(self):
        before = copy.deepcopy((self.data, self.network))
        evidence = self.assess()
        self.assertFalse(evidence["originalSchemaValid"])
        self.assertEqual(evidence["knownWarningCount"], 3)
        self.assertEqual(len(evidence["originalSchemaErrorPaths"]), 2)
        self.assertEqual((self.data, self.network), before)

    def test_failed_or_unfinished_modules_and_final_errors_are_not_waived(self):
        for field in ("errors", "finished"):
            with self.subTest(field=field):
                original = copy.deepcopy(self.status)
                self.status["v1"]["init"][field] = ["failure"] if field == "errors" else None
                with self.assertRaises(ValueError):
                    self.assess()
                self.status = original
        self.result["v1"]["errors"] = ["failure"]
        with self.assertRaises(ValueError):
            self.assess()

    def test_unknown_warning_and_additional_schema_errors_fail(self):
        self.status["v1"]["init"]["recoverable_errors"]["WARNING"].append("another warning")
        with self.assertRaises(ValueError):
            self.assess()
        self.setUp()
        self.data["unknown_secret_field"] = "not echoed"
        with self.assertRaises(ValueError):
            self.assess()

    def test_wrong_path_permissions_owner_and_raw_signature_are_not_generalized(self):
        for key, value in (("path", "/etc/sudoers"), ("owner", "user:user"),
                           ("permission", "0777"), ("encoding", "unknown")):
            with self.subTest(key=key):
                self.setUp()
                self.data["write_files"][0][key] = value
                with self.assertRaises(ValueError):
                    self.assess()

    def test_unknown_network_error_or_mismatched_runtime_annotation_fails(self):
        self.network["config"][0]["subnets"][0]["unexpected"] = True
        with self.assertRaises(ValueError):
            self.assess()
        self.setUp()
        self.network["config"][0]["subnets"][0]["_orig_eni_name"] = "another-interface"
        with self.assertRaises(ValueError):
            self.assess()

    def test_resulting_file_checks_reject_symlink_wrong_content_or_unsafe_mode(self):
        # Exercise main's file checks against actual temp files without touching /etc.
        import tempfile
        import json
        import yaml
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            script = root / "install.sh"
            script.write_text("echo fixture\n")
            seed = yaml.safe_dump(self.data).encode()
            mappings = {
                "/var/lib/cloud/instance/user-data.txt": seed,
                "/var/lib/cloud/data/status.json": json.dumps(self.status).encode(),
                "/var/lib/cloud/data/result.json": json.dumps(self.result).encode(),
                "/var/lib/cloud/instance/network-config.json": yaml.safe_dump(self.network).encode(),
            }
            original_read = pathlib.Path.read_bytes
            original_text = pathlib.Path.read_text
            def read_bytes(path):
                return mappings[str(path)] if str(path) in mappings else original_read(script)
            def read_text(path, *args, **kwargs):
                return mappings[str(path)].decode() if str(path) in mappings else original_text(script)
            fake_schema = types.SimpleNamespace(
                SchemaType=types.SimpleNamespace(CLOUD_CONFIG="cloud", NETWORK_CONFIG_V1="network"),
                get_schema=lambda schema_type: CLOUD_SCHEMA if schema_type == "cloud" else NETWORK_SCHEMA)
            for mode, uid, content in ((0o100777, 0, "echo fixture\n"),
                                       (0o120644, 0, "echo fixture\n"),
                                       (0o100644, 1000, "echo fixture\n"),
                                       (0o100644, 0, "altered")):
                script.write_text(content)
                metadata = types.SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=0)
                with patch.object(policy, "schema", fake_schema), \
                     patch.object(pathlib.Path, "read_bytes", read_bytes), \
                     patch.object(pathlib.Path, "read_text", read_text), \
                     patch.object(pathlib.Path, "is_file", return_value=True), \
                     patch.object(pathlib.Path, "lstat", return_value=metadata):
                    with self.assertRaises(ValueError):
                        policy.main()


if __name__ == "__main__":
    unittest.main()
