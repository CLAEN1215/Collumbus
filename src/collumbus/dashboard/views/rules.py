"""Rules page: documentation and active configuration for all security checks."""

import streamlit as st

from collumbus.config import DEFAULT_CONFIG_PATH, load_config
from collumbus.dashboard.theme import apply_theme
from collumbus.rules import ALL_RULES


def render_rules() -> None:
    apply_theme()
    config = load_config()

    st.title("📋 Security Rules & Policy Catalog")
    st.caption("Inspect the audit checks, security rationales, and active configuration settings.")

    st.markdown(
        "Each rule in Collumbus evaluates a specific resource type and produces a verdict "
        "(Pass, Fail, Error, or Not Applicable). The rule's severity is decoupled from evaluation "
        "logic and configured in `config/rules.yaml`."
    )

    st.divider()

    # Built-in rules
    for rule_cls in ALL_RULES:
        rule_cfg = config.rules.get(rule_cls.rule_id)
        is_enabled = rule_cfg.enabled if rule_cfg else True
        active_sev = rule_cfg.severity.value if rule_cfg else rule_cls.default_severity.value

        status_chip = "🟢 ENABLED" if is_enabled else "⚪ DISABLED"

        sev_label = active_sev.upper()
        expander_title = f"{rule_cls.rule_id}: {rule_cls.title} — [{sev_label}] ({status_chip})"
        with st.expander(expander_title, expanded=True):
            col_r1, col_r2, col_r3 = st.columns(3)
            with col_r1:
                st.markdown(f"**Rule ID:** `{rule_cls.rule_id}`")
                st.markdown(f"**Applies To:** `{', '.join(sorted(rule_cls.resource_types))}`")
            with col_r2:
                st.markdown(f"**Configured Severity:** `{active_sev}`")
                st.markdown(f"**Default Severity:** `{rule_cls.default_severity.value}`")
            with col_r3:
                st.markdown(f"**Status:** {status_chip}")

            st.markdown("##### 🚨 Security Risk & Threat Model")
            st.info(rule_cls.risk)

            st.markdown("##### 🛠️ Remediation Guidance")
            st.code(rule_cls.remediation, language="text")

            if rule_cls.rule_id == "S3-002":
                st.markdown("##### 🔐 Policy: Approved Encryption Algorithms")
                algos = config.s3_encryption.approved_algorithms
                st.code(", ".join(algos))

            if rule_cls.references:
                st.markdown("##### 🔗 Documentation & Benchmarks")
                for url in rule_cls.references:
                    st.markdown(f"- [{url}]({url})")

    # SYS-001 Documentation
    with st.expander("SYS-001: Audit Coverage Gap / Collection Denial (SYSTEM RULE)"):
        st.markdown("**Rule ID:** `SYS-001`")
        st.markdown("**Applies To:** `Collumbus::CoverageGap`")
        st.markdown("**Configured Severity:** `Informational`")
        st.markdown(
            "**Risk**: If the scanning identity is denied permission to list resources or read "
            "attributes (such as `AccessDenied` or `Throttling`), misconfigurations in that area "
            "cannot be verified. Collumbus synthesizes a SYS-001 finding so coverage gaps appear "
            "prominently in reports and cannot be mistaken for clean passes."
        )
        st.markdown("**Remediation Guidance:**")
        st.code("Grant the requested IAM read permission and run the scan again.", language="text")

    st.divider()

    # Active YAML Config File Viewer
    st.subheader("Active Configuration File (`config/rules.yaml`)")
    st.caption(f"Loaded from `{DEFAULT_CONFIG_PATH}`")
    try:
        raw_yaml = DEFAULT_CONFIG_PATH.read_text(encoding="utf-8")
        st.code(raw_yaml, language="yaml")
    except Exception as exc:
        st.error(f"Cannot read config file: {exc}")
