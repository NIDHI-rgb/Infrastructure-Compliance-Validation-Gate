# Infrastructure Compliance Validation Gate

A policy-as-code project that checks Terraform plan JSON against select
NIST SP 800-53 and PCI DSS controls using OPA/Rego. In progress.

Inspired by Bigbadlonewolf/COMPLIANCE_AS_CODE.

## Controls

| ID | Check | PCI DSS | NIST SP 800-53 |
|----|-------|---------|----------------|
| SSH-01 | Public SSH (port 22 open to 0.0.0.0/0) on google_compute_firewall | Req 1 | AC-17 |

More controls are being added.

## Run the tests

    opa test policies/ tests/ssh_security_test.rego -v

## Known limitations

- SSH-01 checks IPv4 0.0.0.0/0 and the exact port "22" only. It does not
  yet detect IPv6 (::/0), port ranges, or rules with no ports listed.
- Tested against hand-written plan fixtures. No cloud account is used.
