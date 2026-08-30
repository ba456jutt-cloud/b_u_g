from tools.base import Tool
import json
import hashlib
from datetime import datetime

class LogAuditTool(Tool):
    name = "log_audit"
    description = "Logs audit data with comprehensive validation and verification."
    parameters = {
        "audit_id": "Unique identifier for the audit",
        "target": "Target URL or IP address",
        "assessment_status": "Status of the assessment",
        "finalization_status": "Finalization status of the audit",
        "severity": "Severity level of the audit",
        "timestamp": "Timestamp of the audit",
        "failure_reason": "Reason for failure if applicable",
        "impact_summary": "Summary of the impact",
        "failed_components": "List of failed components",
        "recommendation": "Recommendation for the audit",
        "action_required": "Boolean indicating if action is required",
        "compliance_notes": "Compliance notes for the audit",
        "verification": "Verification details for the audit",
        "logged_at": "Timestamp when the audit was logged"
    }

    def execute(self, **kwargs) -> str:
        try:
            # Validate all required parameters
            required_params = [
                "audit_id", "target", "assessment_status", "finalization_status",
                "severity", "timestamp", "impact_summary", "failed_components",
                "recommendation", "action_required", "compliance_notes",
                "verification", "logged_at"
            ]
            for param in required_params:
                if param not in kwargs:
                    return f"Error: Missing required parameter {param}"

            # Validate verification parameters
            verification_params = [
                "target_scope_validated", "timestamp_validated",
                "all_fields_present", "immutability_logged",
                "log_entry_created"
            ]
            for param in verification_params:
                if param not in kwargs["verification"]:
                    return f"Error: Missing required verification parameter {param}"

            # Create audit log entry
            audit_log = {
                "audit_id": kwargs["audit_id"],
                "target": kwargs["target"],
                "assessment_status": kwargs["assessment_status"],
                "finalization_status": kwargs["finalization_status"],
                "severity": kwargs["severity"],
                "timestamp": kwargs["timestamp"],
                "failure_reason": kwargs.get("failure_reason", ""),
                "impact_summary": kwargs["impact_summary"],
                "failed_components": kwargs["failed_components"],
                "recommendation": kwargs["recommendation"],
                "action_required": kwargs["action_required"],
                "compliance_notes": kwargs["compliance_notes"],
                "verification": kwargs["verification"],
                "logged_at": kwargs["logged_at"]
            }

            # Generate hash for immutability verification
            audit_log_hash = hashlib.sha256(json.dumps(audit_log, sort_keys=True).encode()).hexdigest()
            audit_log["hash"] = audit_log_hash

            # Log the audit data
            with open("audit_log.json", "a") as f:
                json.dump(audit_log, f)
                f.write("\n")

            return "Audit logged successfully"
        except Exception as e:
            return f"Error: {str(e)}"