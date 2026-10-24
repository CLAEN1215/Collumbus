"""Rules page: documentation and active configuration for all security checks."""

import streamlit as st

from collumbus.config import DEFAULT_CONFIG_PATH, load_config
from collumbus.dashboard.theme import apply_theme
from collumbus.rules import ALL_RULES


def render_rules() -> None:
    apply_theme()
    config = load_config()

    # 1. Nocturn Page Header
    st.markdown(
        "<h1 style='font-size: 2.3rem; font-weight: 800; color: #ffffff; "
        "margin-bottom: 2px;'>Rules</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='color: #8e90a6; font-size: 0.95rem; margin-bottom: 1.5rem;'>"
        "Security audit check catalog &bull; CIS benchmark mappings, "
        "threat scenarios, and active configuration settings.</p>",
        unsafe_allow_html=True,
    )

    # 2. Service Filter Selector (Nocturn Pill Tabs)
    service_filter = st.radio(
        "Filter by Cloud Domain",
        options=[
            "All (5)",
            "Storage (S3)",
            "Identity (IAM)",
            "Auditing (CloudTrail)",
            "System",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )

    st.write("")

    # 3. Rule Cards
    for rule_cls in ALL_RULES:
        if "Storage" in service_filter and not any("S3" in rt for rt in rule_cls.resource_types):
            continue
        if "Identity" in service_filter and not any("IAM" in rt for rt in rule_cls.resource_types):
            continue
        if "Auditing" in service_filter and not any(
            "CloudTrail" in rt for rt in rule_cls.resource_types
        ):
            continue
        if "System" in service_filter:
            continue

        rule_cfg = config.rules.get(rule_cls.rule_id)
        is_enabled = rule_cfg.enabled if rule_cfg else True
        active_sev = rule_cfg.severity.value if rule_cfg else rule_cls.default_severity.value

        status_chip = "ENABLED" if is_enabled else "DISABLED"
        sev_label = active_sev.upper()

        card_title = f"[{rule_cls.rule_id}] {rule_cls.title} — [{sev_label}] ({status_chip})"

        with st.expander(card_title, expanded=True):
            st.markdown(f"### {rule_cls.title}")

            # Metadata grid
            with st.container(border=True):
                col_r1, col_r2, col_r3 = st.columns(3)
                with col_r1:
                    st.caption(f"**Rule ID:** `{rule_cls.rule_id}`")
                    rt_str = ", ".join(sorted(rule_cls.resource_types))
                    st.caption(f"**Target Types:** `{rt_str}`")
                with col_r2:
                    st.caption(f"**Configured Severity:** `{active_sev}`")
                    st.caption(f"**Default Severity:** `{rule_cls.default_severity.value}`")
                with col_r3:
                    st.caption(f"**Status:** `{status_chip}`")
                    st.caption("**Config:** `config/rules.yaml`")

            # Risk & Threat Model
            st.markdown(
                "<div style='background: #181928; border-left: 3px solid #8b5cf6; "
                "border-radius: 0 10px 10px 0; padding: 12px 16px; margin: 12px 0;'>"
                "<div style='font-size: 0.8rem; font-weight: 700; color: #a78bfa; "
                "text-transform: uppercase; margin-bottom: 4px;'>Threat Scenario</div>"
                f"<div style='font-size: 0.85rem; color: #d4d4d8;'>{rule_cls.risk}</div>"
                "</div>",
                unsafe_allow_html=True,
            )

            # Remediation Guidance
            st.markdown(
                "<span style='font-size: 0.85rem; font-weight: 700; color: #ffffff;'>"
                "Standard Remediation:</span>",
                unsafe_allow_html=True,
            )
            st.code(rule_cls.remediation, language="text")

            # Special config info (e.g. S3 approved encryption algorithms)
            if rule_cls.rule_id == "S3-002":
                with st.container(border=True):
                    st.markdown(
                        "<div style='font-size: 0.85rem; font-weight: 700; color: #ffffff;'>"
                        "Approved Encryption Algorithms</div>",
                        unsafe_allow_html=True,
                    )
                    algos = config.s3_encryption.approved_algorithms
                    st.caption(f"Active in config: {', '.join(algos)}")

            # References & Compliance Frameworks
            if rule_cls.references:
                with st.expander("Benchmark References", expanded=False):
                    for url in rule_cls.references:
                        st.markdown(f"- [{url}]({url})")

    # 4. System Rule: SYS-001
    if "System" in service_filter or "All" in service_filter:
        with st.expander(
            "[SYS-001] Audit Coverage Gap / Collection Denial — [INFORMATIONAL] (SYSTEM)",
            expanded=("System" in service_filter),
        ):
            st.markdown("### Audit Coverage Gap / Collection Denial")

            with st.container(border=True):
                sys_col1, sys_col2, sys_col3 = st.columns(3)
                with sys_col1:
                    st.caption("**Rule ID:** `SYS-001`")
                    st.caption("**Target:** `Columbus::CoverageGap`")
                with sys_col2:
                    st.caption("**Severity:** `Informational`")
                    st.caption("**Category:** `Audit Engine Transparency`")
                with sys_col3:
                    st.caption("**Status:** `ALWAYS ACTIVE`")
                    st.caption("**Source:** `Built-in Engine`")

            st.markdown(
                "<div style='background: #181928; border-left: 3px solid #8b5cf6; "
                "border-radius: 0 10px 10px 0; padding: 12px 16px; margin: 12px 0;'>"
                "<div style='font-size: 0.8rem; font-weight: 700; color: #a78bfa; "
                "text-transform: uppercase; margin-bottom: 4px;'>Threat Scenario</div>"
                "<div style='font-size: 0.85rem; color: #d4d4d8;'>"
                "If the scanning identity is denied permission to read attributes "
                "(such as AccessDenied or Throttling), misconfigurations cannot be verified. "
                "Columbus flags coverage gaps as Errors so uninspected areas cannot be mistaken "
                "for clean passes.</div></div>",
                unsafe_allow_html=True,
            )

            st.markdown(
                "<span style='font-size: 0.85rem; font-weight: 700; color: #ffffff;'>"
                "Standard Remediation:</span>",
                unsafe_allow_html=True,
            )
            st.code(
                "Grant the requested read-only IAM permission to the scanning identity "
                "and re-execute the scan.",
                language="text",
            )

    st.write("")

    # 5. Active YAML Config Viewer
    with st.expander("Active Policy Configuration (`config/rules.yaml`)"):
        st.caption(f"Loaded directly from: `{DEFAULT_CONFIG_PATH}`")
        try:
            raw_yaml = DEFAULT_CONFIG_PATH.read_text(encoding="utf-8")
            st.code(raw_yaml, language="yaml")
        except Exception as exc:
            st.error(f"Cannot read config file: {exc}")
