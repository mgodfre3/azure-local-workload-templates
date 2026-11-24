# Contributing

Open an issue describing the workload, guest OS and Azure Local release before widening the supported matrix. Keep changes scoped, reuse the shared VM/monitoring modules, and add focused tests for new behavior.

Run `scripts/Test.ps1` with PowerShell 7.4+, Pester 5.7.1+, Bicep 0.42.1+ and Python 3.10+ with `python -m pip install -r tests/requirements.txt`. The Python policy tests use real JSON-schema validation without requiring cloud-init on the workstation. On Linux also run `sh -n guest/configure-nginx.sh`. Tests and CI must not authenticate to Azure, create infrastructure, accept paid terms, or depend on a customer's stamp.

Describe live tests separately from offline checks. Never contribute customer identifiers, local answer files, credentials, private keys, SAS URLs, internal-only documentation, or deployment logs. Supply sanitized reproducible examples. Do not weaken existing-disk safety, credential handling, image support checks, ownership checks, or network allowlists to make a deployment pass.

By contributing, you agree to license your contributions under the repository's MIT license.
