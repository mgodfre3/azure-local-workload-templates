#!/usr/bin/env python3
"""Verify the explicitly selected Azure Local warning policy without editing inputs."""
import copy
import hashlib
import json
import pathlib
import shlex
import stat
import sys

import jsonschema
import yaml
from cloudinit.config import schema


WARNINGS = {
    "cloud-config failed schema validation! You may run 'sudo cloud-init schema --system' to check the details.",
    "Unknown encoding type raw, assuming text/plain",
    "network-config-v1 failed schema validation! You may run 'sudo cloud-init schema --system' to check the details.",
}
AGENT_SCRIPT = "/opt/wssd/installGuestAgentScript.sh"
PHASES = {"init", "init-local", "modules-config", "modules-final"}


def assess(user_data, status, result, network, cloud_schema, network_schema):
    phases = status.get("v1", {})
    if not PHASES.issubset(phases) or any(
        not isinstance(phases[name], dict) or phases[name].get("errors") != []
        or not phases[name].get("finished")
        for name in PHASES
    ):
        raise ValueError("cloud-init phases are incomplete or have errors")
    if result.get("v1", {}).get("errors") != []:
        raise ValueError("cloud-init final result has errors or is missing")
    warnings = []
    for phase in phases.values():
        if not isinstance(phase, dict):
            continue
        recoverable = phase.get("recoverable_errors", {})
        if not isinstance(recoverable, dict):
            raise ValueError("unexpected recoverable-error shape")
        for category, messages in recoverable.items():
            if not isinstance(messages, list) or category != "WARNING" or any(
                not isinstance(message, str) or message not in WARNINGS for message in messages
            ):
                raise ValueError("unrecognized cloud-init recoverable error")
            warnings.extend(messages)
    if not isinstance(user_data, dict):
        raise ValueError("cloud-config is not an object")
    validator = jsonschema.Draft4Validator(cloud_schema)
    errors = list(validator.iter_errors(user_data))
    corrected = copy.deepcopy(user_data)
    paths = []
    for index, row in enumerate(corrected.get("write_files", [])):
        if "permission" in row or row.get("encoding") == "raw":
            if (
                row.get("path") != AGENT_SCRIPT or row.get("owner") != "root:root"
                or set(row) != {"path", "owner", "content", "permission", "encoding"}
                or row["permission"] != "0744" or row["encoding"] != "raw"
                or not isinstance(row["content"], str)
            ):
                raise ValueError("unrecognized provider write_files signature")
            row["permissions"] = row.pop("permission")
            row["encoding"] = "text/plain"
            paths.extend([["write_files", index, "permission"], ["write_files", index, "encoding"]])
    if errors and (len(errors) != len(paths) or not paths):
        raise ValueError("unrecognized cloud-config schema errors")
    if list(validator.iter_errors(corrected)):
        raise ValueError("additional cloud-config schema errors")
    if errors:
        expected = {(tuple(path[:-1]), "additionalProperties") if path[-1] == "permission"
                    else (tuple(path), "enum") for path in paths}
        if {(tuple(error.absolute_path), error.validator) for error in errors} != expected:
            raise ValueError("unexpected cloud-config error paths")
    network_validator = jsonschema.Draft4Validator(network_schema)
    network_errors = list(network_validator.iter_errors(network))
    corrected_network = copy.deepcopy(network)
    network_paths = []
    if not isinstance(corrected_network, dict) or corrected_network.get("version") != 1:
        raise ValueError("expected cached network-config v1")
    for index, interface in enumerate(corrected_network.get("config", [])):
        for subnet_index, subnet in enumerate(interface.get("subnets", [])):
            if "_orig_eni_name" in subnet:
                if subnet["_orig_eni_name"] != interface.get("name"):
                    raise ValueError("unexpected runtime network annotation")
                del subnet["_orig_eni_name"]
                network_paths.append(["config", index, "subnets", subnet_index, "_orig_eni_name"])
    if network_errors and not network_paths:
        raise ValueError("unrecognized network schema error")
    if list(network_validator.iter_errors(corrected_network)):
        raise ValueError("additional network schema errors")
    if warnings and not errors and not network_errors:
        raise ValueError("warnings are not explained by the inspected artifacts")
    return {
        "policy": "azureLocalKnownWarnings",
        "originalSchemaValid": not errors,
        "originalSchemaErrorPaths": paths,
        "cachedNetworkSchemaValid": not network_errors,
        "runtimeNetworkAnnotationPaths": network_paths,
        "knownWarningCount": len(warnings),
    }


def main():
    seed = pathlib.Path("/var/lib/cloud/instance/user-data.txt")
    seed_bytes = seed.read_bytes()
    user_data = yaml.safe_load(seed_bytes)
    status = json.loads(pathlib.Path("/var/lib/cloud/data/status.json").read_text())
    result = json.loads(pathlib.Path("/var/lib/cloud/data/result.json").read_text())
    network_path = pathlib.Path("/var/lib/cloud/instance/network-config.json")
    if not network_path.is_file():
        raise ValueError("cached network input unavailable; warning policy cannot be verified")
    network_bytes = network_path.read_bytes()
    evidence = assess(
        user_data, status, result, yaml.safe_load(network_bytes),
        schema.get_schema(schema_type=schema.SchemaType.CLOUD_CONFIG),
        schema.get_schema(schema_type=schema.SchemaType.NETWORK_CONFIG_V1),
    )
    commands = user_data.get("runcmd", [])
    for row in user_data.get("write_files", []):
        if row.get("path") != AGENT_SCRIPT:
            continue
        path = pathlib.Path(AGENT_SCRIPT)
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) not in (0o644, 0o744)
            or path.read_bytes() != row["content"].encode()
        ):
            raise ValueError("generated agent script content, ownership or mode is unsafe")
        parsed = [shlex.split(command) if isinstance(command, str) else command for command in commands]
        if not any(
            isinstance(command, list) and len(command) >= 2
            and command[0] in ("bash", "/bin/bash", "sh", "/bin/sh")
            and command[1] == AGENT_SCRIPT for command in parsed
        ):
            raise ValueError("generated nonexecutable script is not explicitly shell-invoked")
    evidence["originalUserDataSha256"] = hashlib.sha256(seed_bytes).hexdigest()
    evidence["cachedNetworkSha256"] = hashlib.sha256(network_bytes).hexdigest()
    evidence["sourcePreparationCertified"] = False
    print("CLOUD_INIT_EVIDENCE=" + json.dumps(evidence, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, yaml.YAMLError, jsonschema.SchemaError):
        # Provider data can contain credentials. Never include a reflected payload or exception.
        print("Linux image acceptance failed: known-warning policy could not verify original provisioning evidence", file=sys.stderr)
        sys.exit(1)
