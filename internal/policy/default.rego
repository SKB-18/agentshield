package agentshield.authz

import future.keywords

# Default Deny Invariant: All decisions default to DENY unless an explicit rule matches
default decision = "DENY"
default allowed = false
default requires_approval = false

# Rule Condition 1: Tenant Mismatch
is_tenant_mismatch if {
    input.action.resource_id != ""
    contains(input.action.resource_id, "tenant-")
    not contains(input.action.resource_id, input.identity.tenant_id)
}

# Rule Condition 2: Egress / Destination Exfiltration Check
is_unauthorized_destination if {
    input.tool.id == "send_email"
    to_addr := input.action.arguments.to
    not endswith(lower(to_addr), "@company.internal")
    not endswith(lower(to_addr), "@corp.internal")
}

is_unauthorized_destination if {
    input.tool.id == "export_data"
    dest := input.action.arguments.destination_url
    not startswith(dest, "https://export.partner.com")
    not startswith(dest, "s3.corporate.internal")
}

# Rule Condition 3: Reader Allow
is_reader_allow if {
    input.identity.role == "reader"
    input.tool.risk == "low"
    input.tool.id == "search_docs"
    not is_tenant_mismatch
    not is_unauthorized_destination
}

# Rule Condition 4: Analyst Standard Allow
is_analyst_allow if {
    input.identity.role == "analyst"
    input.tool.risk in ["low", "medium"]
    input.tool.id in ["search_docs", "query_db", "read_file"]
    not is_tenant_mismatch
    not is_unauthorized_destination
}

# Rule Condition 5: Analyst High Risk Require Approval
is_analyst_approve if {
    input.identity.role == "analyst"
    input.tool.risk == "high"
    not is_tenant_mismatch
    not is_unauthorized_destination
}

# Rule Condition 6: Admin Elevated Allow
is_admin_allow if {
    input.identity.role == "admin"
    input.tool.risk in ["low", "medium", "high"]
    not is_tenant_mismatch
    not is_unauthorized_destination
}

# Rule Condition 7: Admin Critical Risk Require Approval
is_admin_approve if {
    input.identity.role == "admin"
    input.tool.risk == "critical"
    not is_tenant_mismatch
    not is_unauthorized_destination
}

# Aggregator: Any valid specific rule matched
any_matched_rule if { is_tenant_mismatch }
any_matched_rule if { is_unauthorized_destination }
any_matched_rule if { is_reader_allow }
any_matched_rule if { is_analyst_allow }
any_matched_rule if { is_analyst_approve }
any_matched_rule if { is_admin_allow }
any_matched_rule if { is_admin_approve }

# Decisions
decision = "DENY" if { is_tenant_mismatch }
rule_ids contains "RULE_TENANT_MISMATCH" if { is_tenant_mismatch }
reasons contains "Cross-tenant access violation: resource tenant does not match agent tenant" if { is_tenant_mismatch }

decision = "DENY" if { is_unauthorized_destination; not is_tenant_mismatch }
rule_ids contains "RULE_UNAUTHORIZED_DESTINATION" if { is_unauthorized_destination; not is_tenant_mismatch }
reasons contains "Prohibited destination: external exfiltration or unapproved recipient domain" if { is_unauthorized_destination; not is_tenant_mismatch }

decision = "ALLOW" if { is_reader_allow }
rule_ids contains "RULE_READER_LOW_RISK_ALLOW" if { is_reader_allow }
reasons contains "Reader role authorized for low-risk read-only document search" if { is_reader_allow }

decision = "ALLOW" if { is_analyst_allow }
rule_ids contains "RULE_ANALYST_STANDARD_ALLOW" if { is_analyst_allow }
reasons contains "Analyst role authorized for standard analytical query tools" if { is_analyst_allow }

decision = "APPROVE" if { is_analyst_approve }
rule_ids contains "RULE_ANALYST_HIGH_RISK_REQUIRE_APPROVAL" if { is_analyst_approve }
reasons contains "High-risk tool call requires human authorization approval envelope" if { is_analyst_approve }

decision = "ALLOW" if { is_admin_allow }
rule_ids contains "RULE_ADMIN_ELEVATED_ALLOW" if { is_admin_allow }
reasons contains "Administrator role authorized for elevated tool execution" if { is_admin_allow }

decision = "APPROVE" if { is_admin_approve }
rule_ids contains "RULE_CRITICAL_RISK_REQUIRE_APPROVAL" if { is_admin_approve }
reasons contains "Critical system operation requires multi-party human approval" if { is_admin_approve }

# Flags
allowed if { decision == "ALLOW" }
requires_approval if { decision == "APPROVE" }

# Fallback: Default Deny
decision = "DENY" if { not any_matched_rule }
rule_ids contains "RULE_DEFAULT_DENY" if { not any_matched_rule }
reasons contains "Default Deny: No matching policy authorization rule found for this role and tool combination" if { not any_matched_rule }
