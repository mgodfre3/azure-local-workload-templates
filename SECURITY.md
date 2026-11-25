# Security

Do not put credentials, private keys, customer answer files or raw deployment/extension logs in public issues. Report sensitive vulnerabilities through GitHub's private vulnerability reporting feature if available; otherwise contact the repository owner privately before disclosing details.

These initial templates require privileged Azure deployment access and run guest code as SYSTEM/root. Review all scripts before use and test on dedicated lab VMs. This project is not a production hardening baseline, backup solution, or guarantee of Microsoft product support.

The deployment preserves resources after failures; review partial infrastructure and ongoing charges. Ownership tags are collision-prevention metadata, not an authorization boundary. Protect the Azure deployment host, service connection, repository branch and customer answer files.
