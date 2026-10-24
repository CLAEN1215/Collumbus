"""Rules page: documentation and active configuration for all security checks.

Built using the 7 Principles of Design:
1. Contrast - High-visibility status chips, severity badges, and code blocks.
2. Hierarchy - Filter by cloud service, rule overview, threat model, and fix guide.
3. Alignment - Structured metadata columns and aligned benchmark references.
4. Balance - Symmetrical card layouts across all rule definitions.
5. Proximity - Risk impact and remediation commands grouped within each rule card.
6. Repetition - Consistent card templates and styling across all rules.
7. White Space - Uncluttered layout with progressive disclosure for config YAML.
"""

import streamlit as st

from collumbus.config import DEFAULT_CONFIG_PATH, load_config
from collumbus.dashboard.theme import apply_theme
from collumbus.rules import ALL_RULES


def render_rules() -> None:
    apply_theme()
    config = load_config()

    st.title("📋 Security Rules & Policy Catalog")
    st.caption(
        "Inspect active audit checks, CIS benchmark mappings, threat models, "
        "and configuration rules."
    )

    st.markdown(
        "Collumbus enforces a strict separation of concerns: each rule assesses a specific "
        "cloud resource type, while severity and enablement are dynamically controlled via "
        "`config/rules.yaml` without changing audit logic."
    )

    st.divider()

    # 1. Service Filter Selector (Hierarchy & Contrast)
    service_filter = st.radio(
        "Filter by Cloud Domain",
        options=[
            "All Rules (5)",
            "Storage (S3)",
            "Identity & Access (IAM)",
            "Auditing & Logging (CloudTrail)",
            "System & Coverage",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )

    st.write("")

    # 2. Rule Cards (Repetition, Proximity & Contrast)
    for rule_cls in ALL_RULES:
        # Service domain filtering
        if "Storage" in service_filter and not any("S3" in rt for rt in rule_cls.resource_types):
            continue
        if "Identity" in service_filter and not any("IAM" in rt for rt in rule_cls.resource_types):
            continue
        if "Auditing" in service_filter and not any(
            "CloudTrail" in rt for rt in rule_cls.resource_types
        ):
            continue
        if "System" in service_filter:
            continue  # System rules are rendered below

        rule_cfg = config.rules.get(rule_cls.rule_id)
        is_enabled = rule_cfg.enabled if rule_cfg else True
        active_sev = rule_cfg.severity.value if rule_cfg else rule_cls.default_severity.value

        status_chip = "🟢 ENABLED" if is_enabled else "⚪ DISABLED"
        sev_label = active_sev.upper()

        card_title = f"[{rule_cls.rule_id}] {rule_cls.title} — [{sev_label}] ({status_chip})"

        with st.expander(card_title, expanded=True):
            st.markdown(f"### {rule_cls.title}")

            # Metadata grid (Alignment & Balance)
            with st.container(border=True):
                col_r1, col_r2, col_r3 = st.columns(3)
                with col_r1:
                    st.caption(f"**Rule ID:** `{rule_cls.rule_id}`")
                    rt_str = ", ".join(sorted(rule_cls.resource_types))
                    st.caption(f"**Resource Types:** `{rt_str}`")
                with col_r2:
                    st.caption(f"**Active Severity:** `{active_sev}`")
                    st.caption(f"**Default Severity:** `{rule_cls.default_severity.value}`")
                with col_r3:
                    st.caption(f"**Evaluation Status:** {status_chip}")
                    st.caption("**Config Source:** `config/rules.yaml`")

            # Risk & Threat Model (Proximity & Contrast)
            st.markdown("#### 🚨 Security Risk & Threat Model")
            st.info(rule_cls.risk)

            # Remediation Guidance (Proximity & Hierarchy)
            st.markdown("#### 🛠️ Recommended Remediation")
            st.code(rule_cls.remediation, language="text")

            # Special config info (e.g. S3 approved encryption algorithms)
            if rule_cls.rule_id == "S3-002":
                with st.container(border=True):
                    st.markdown("##### 🔐 Policy: Approved Server-Side Encryption Algorithms")
                    algos = config.s3_encryption.approved_algorithms
                    st.caption(f"Configured in `config/rules.yaml`: **{', '.join(algos)}**")

            # References & Compliance Frameworks (White Space)
            if rule_cls.references:
                st.markdown("#### 🔗 Benchmark References & Documentation")
                for url in rule_cls.references:
                    st.markdown(f"- [{url}]({url})")

    # 3. System Rule: SYS-001 (Audit Coverage Gap / Collection Denial)
    if "System" in service_filter or "All Rules" in service_filter:
        with st.expander(
            "[SYS-001] Audit Coverage Gap / Collection Denial — [INFORMATIONAL] (🟢 SYSTEM ENGINE)",
            expanded=("System" in service_filter),
        ):
            st.markdown("### Audit Coverage Gap / Collection Denial")

            with st.container(border=True):
                sys_col1, sys_col2, sys_col3 = st.columns(3)
                with sys_col1:
                    st.caption("**Rule ID:** `SYS-001`")
                    st.caption("**Resource Types:** `Collumbus::CoverageGap`")
                with sys_col2:
                    st.caption("**Severity:** `Informational`")
                    st.caption("**Category:** `Audit Engine Transparency`")
                with sys_col3:
                    st.caption("**Evaluation Status:** 🟢 ALWAYS ACTIVE")
                    st.caption("**Config Source:** `Built-in Engine`")

            st.markdown("#### 🚨 Security Risk & Threat Model")
            st.info(
                "If the scanning identity is denied permission to list resources or read "
                "attributes (such as `AccessDenied` or `Throttling`), misconfigurations "
                "in that area cannot be verified. Collumbus synthesizes a SYS-001 finding "
                "so coverage gaps appear prominently in reports and cannot be mistaken "
                "for clean passes."
            )

            st.markdown("#### 🛠️ Recommended Remediation")
            st.code(
                "Grant the requested read-only IAM permission to the scanning identity "
                "and re-execute the scan.",
                language="text",
            )

    st.divider()

    # 4. Active YAML Config Viewer (White Space & Transparency)
    with st.expander("📄 View Active Policy Configuration (`config/rules.yaml`)"):
        st.caption(f"Loaded directly from: `{DEFAULT_CONFIG_PATH}`")
        try:
            raw_yaml = DEFAULT_CONFIG_PATH.read_text(encoding="utf-8")
            st.code(raw_yaml, language="yaml")
        except Exception as exc:
            st.error(f"Cannot read config file: {exc}")
