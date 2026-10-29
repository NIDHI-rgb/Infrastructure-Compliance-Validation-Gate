package terraform_compliance.ssh_test

import rego.v1
import data.terraform_compliance.ssh

test_public_ssh_is_denied if {
    test_input := {
        "resource_changes": [{
            "address": "google_compute_firewall.allow_ssh_public",
            "type": "google_compute_firewall",
            "change": {
                "actions": ["create"],
                "after": {
                    "direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": [{
                        "protocol": "tcp",
                        "ports": ["22"],
                    }],
                },
            },
        }],
    }

    count(ssh.deny) == 1 with input as test_input
}

test_restricted_ssh_is_allowed if {
    test_input := {
        "resource_changes": [{
            "address": "google_compute_firewall.allow_ssh_restricted",
            "type": "google_compute_firewall",
            "change": {
                "actions": ["create"],
                "after": {
                    "direction": "INGRESS",
                    "source_ranges": ["203.0.113.10/32"],
                    "allow": [{
                        "protocol": "tcp",
                        "ports": ["22"],
                    }],
                },
            },
        }],
    }

    count(ssh.deny) == 0 with input as test_input
}