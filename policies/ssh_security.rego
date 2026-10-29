package terraform_compliance.ssh

import rego.v1

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"
    resource.change.actions[_] in {"create", "update"}

    after := resource.change.after
    after.direction == "INGRESS"
    after.source_ranges[_] == "0.0.0.0/0"

    allow := after.allow[_]
    allow.ports[_] == "22"

    msg := sprintf(
        "NIST AC-17 | PCI DSS Req 1 | %s: SSH port 22 is exposed to the internet. Restrict source_ranges to trusted IP ranges.",
        [resource.address],
    )
}
