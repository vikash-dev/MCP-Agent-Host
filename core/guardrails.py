"""
Guardrails & Policy Middleware
------------------------------
Enforces target scope allowlists (domains, CIDRs, file paths), execution timeouts,
output truncation context limits, and Human-in-the-Loop (HITL) operator approvals.
"""

import os
import json
import fnmatch
import ipaddress
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple


class PolicyViolationError(Exception):
    """Raised when a tool call violates security or scope policy."""
    pass


class ScopeViolationError(PolicyViolationError):
    """Raised when a target domain, IP, or path is outside authorized scope."""
    pass


class HITLRejectionError(PolicyViolationError):
    """Raised when a human operator rejects execution of a sensitive tool."""
    pass


class GuardrailsMiddleware:
    def __init__(
        self,
        policy_path: str = "config/policy.json",
        auto_approve: bool = False,
        hitl_callback: Optional[Callable[[str, Dict[str, Any]], bool]] = None
    ):
        self.policy_path = os.path.abspath(policy_path)
        self.auto_approve = auto_approve
        self.hitl_callback = hitl_callback
        self.policy = self._load_policy()

    def _load_policy(self) -> Dict[str, Any]:
        """Loads and parses the policy configuration file."""
        if not os.path.exists(self.policy_path):
            return {
                "scope": {"allowed_domains": ["*"], "allowed_cidrs": [], "allowed_paths": ["."]},
                "execution_limits": {"timeout_seconds": 30, "max_output_chars": 4000},
                "human_in_the_loop": {"default_requires_approval": False, "sensitive_tools": []}
            }

        with open(self.policy_path, "r", encoding="utf-8") as f:
            return json.load(f)

    @property
    def timeout_seconds(self) -> int:
        return self.policy.get("execution_limits", {}).get("timeout_seconds", 30)

    @property
    def max_output_chars(self) -> int:
        return self.policy.get("execution_limits", {}).get("max_output_chars", 4000)

    @property
    def allowed_domains(self) -> List[str]:
        return self.policy.get("scope", {}).get("allowed_domains", [])

    @property
    def allowed_cidrs(self) -> List[str]:
        return self.policy.get("scope", {}).get("allowed_cidrs", [])

    @property
    def allowed_paths(self) -> List[str]:
        return self.policy.get("scope", {}).get("allowed_paths", [])

    @property
    def sensitive_tools(self) -> List[str]:
        return self.policy.get("human_in_the_loop", {}).get("sensitive_tools", [])

    # =========================================================================
    # Scope Checking
    # =========================================================================

    def is_domain_allowed(self, target: str) -> bool:
        """Checks if a domain or hostname is in the allowed scope."""
        target = target.lower().strip()
        # Strip port if present
        if ":" in target:
            target = target.split(":")[0]

        for pattern in self.allowed_domains:
            pattern = pattern.lower().strip()
            if pattern == "*":
                return True
            if pattern.startswith("*."):
                root = pattern[2:]
                if target == root or target.endswith("." + root):
                    return True
            elif fnmatch.fnmatch(target, pattern):
                return True
            elif target == pattern:
                return True
        return False

    def is_ip_allowed(self, ip_str: str) -> bool:
        """Checks if an IP address belongs to an authorized CIDR."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            for cidr_str in self.allowed_cidrs:
                network = ipaddress.ip_network(cidr_str.strip(), strict=False)
                if ip in network:
                    return True
        except ValueError:
            pass
        return False

    def is_path_allowed(self, file_path: str) -> bool:
        """Checks if a local path is within allowed directories."""
        canonical_target = os.path.abspath(file_path)
        for allowed in self.allowed_paths:
            canonical_allowed = os.path.abspath(allowed)
            try:
                # Check if canonical_target is subpath of canonical_allowed
                common = os.path.commonpath([canonical_target, canonical_allowed])
                if common == canonical_allowed:
                    return True
            except ValueError:
                # Different drive letters on Windows
                continue
        return False

    def validate_scope(self, tool_name: str, arguments: Dict[str, Any]) -> None:
        """
        Validates all tool arguments against authorized target scope.
        Inspects URLs, hostnames, IPs, and local filesystem paths.
        """
        for key, value in arguments.items():
            if not isinstance(value, str):
                continue

            val = value.strip()

            # Check for URL parameters
            if val.startswith(("http://", "https://")):
                parsed = urllib.parse.urlparse(val)
                hostname = parsed.hostname or ""
                if not hostname:
                    raise ScopeViolationError(f"Argument '{key}' contains an unparseable URL target: '{val}'")

                # Verify domain or IP
                allowed = self.is_domain_allowed(hostname) or self.is_ip_allowed(hostname)
                if not allowed:
                    raise ScopeViolationError(
                        f"Target host '{hostname}' (from '{key}') is NOT in the authorized scope allowlist. "
                        f"Allowed domains: {self.allowed_domains}, Allowed CIDRs: {self.allowed_cidrs}"
                    )

            # Check for standalone domain or hostname targets
            elif key in ["hostname", "target", "target_url", "host", "domain"]:
                allowed = self.is_domain_allowed(val) or self.is_ip_allowed(val)
                if not allowed:
                    raise ScopeViolationError(
                        f"Target '{val}' (from '{key}') is NOT in the authorized scope allowlist. "
                        f"Allowed domains: {self.allowed_domains}, Allowed CIDRs: {self.allowed_cidrs}"
                    )

            # Check for file path targets
            elif key in ["log_path", "file_path", "path", "dir_path"] or ("/" in val or "\\" in val):
                # Verify that path is allowed
                if not self.is_path_allowed(val):
                    raise ScopeViolationError(
                        f"Path '{val}' (from '{key}') is outside the authorized paths allowlist. "
                        f"Authorized paths: {self.allowed_paths}"
                    )

    # =========================================================================
    # Human-in-the-Loop (HITL) Check
    # =========================================================================

    def check_hitl_approval(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        server_config: Dict[str, Any]
    ) -> None:
        """
        Verifies operator approval for sensitive tools or servers flagged for HITL.
        """
        # Determine if approval is required
        server_requires_approval = server_config.get("requires_approval", False)
        server_tools_approval = server_config.get("tools_require_approval", [])
        tool_in_server_list = tool_name in server_tools_approval or tool_name.split("__")[-1] in server_tools_approval
        tool_in_policy_list = tool_name in self.sensitive_tools or tool_name.split("__")[-1] in self.sensitive_tools
        default_policy_approval = self.policy.get("human_in_the_loop", {}).get("default_requires_approval", False)

        needs_approval = (
            server_requires_approval or
            tool_in_server_list or
            tool_in_policy_list or
            default_policy_approval
        )

        if not needs_approval:
            return

        if self.auto_approve:
            return

        # Use custom callback if provided
        if self.hitl_callback is not None:
            approved = self.hitl_callback(tool_name, arguments)
            if not approved:
                raise HITLRejectionError(f"Tool '{tool_name}' rejected by operator via HITL callback.")
            return

        # Fallback to interactive console prompt
        print("\n" + "=" * 65)
        print("  ⚠️  HUMAN-IN-THE-LOOP (HITL) OPERATOR APPROVAL REQUIRED")
        print("=" * 65)
        print(f"  Tool Name : {tool_name}")
        print(f"  Server    : {server_config.get('name', 'unknown')}")
        print(f"  Arguments : {json.dumps(arguments, indent=2)}")
        print("=" * 65)

        try:
            choice = input("  Proceed with execution? [y/N]: ").strip().lower()
            if choice not in ["y", "yes"]:
                raise HITLRejectionError(f"Operator rejected execution of tool '{tool_name}'.")
        except (EOFError, OSError):
            raise HITLRejectionError(f"No interactive input available to approve sensitive tool '{tool_name}'.")

    # =========================================================================
    # Output Truncation
    # =========================================================================

    def truncate_output(self, raw_output: str, artifact_path: Optional[str] = None) -> Tuple[str, bool]:
        """
        Truncates tool output if it exceeds max_output_chars so large outputs
        do not overflow the LLM context window. Full output is preserved in the evidence store.
        """
        if not raw_output or len(raw_output) <= self.max_output_chars:
            return raw_output, False

        kept_length = self.max_output_chars - 300
        truncated_text = raw_output[:kept_length]

        ref_note = f"in Evidence Store artifact: '{artifact_path}'" if artifact_path else "in the local Evidence Store"
        truncation_footer = (
            f"\n\n[... TRUNCATED: Output exceeded safety limit of {self.max_output_chars} characters. "
            f"Original size: {len(raw_output)} characters. Full raw output is safely preserved {ref_note}.]"
        )

        return truncated_text + truncation_footer, True
