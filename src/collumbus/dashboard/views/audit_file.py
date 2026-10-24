"""Audit by File: Drag & drop or paste AWS JSON documents for instant vulnerability auditing."""

import streamlit as st

from collumbus.collectors import FileParseError
from collumbus.dashboard.state import get_active_scan, run_and_save_content_scan
from collumbus.dashboard.theme import apply_theme
from collumbus.models import Finding, Severity, Status

SAMPLE_VULNERABLE_IAM = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAllAdminActions",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}"""

SAMPLE_SECURE_IAM = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadOnlyS3Buckets",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::company-data-vault",
        "arn:aws:s3:::company-data-vault/*"
      ]
    }
  ]
}"""

SAMPLE_VULNERABLE_S3 = """{
  "BucketName": "marketing-unprotected-files",
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": false,
    "IgnorePublicAcls": false,
    "BlockPublicPolicy": false,
    "RestrictPublicBuckets": false
  }
}"""

SAMPLE_CLOUDFORMATION = """{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Company CloudFormation Stack with S3 and IAM",
  "Resources": {
    "UnsecuredBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "public-insecure-assets",
        "PublicAccessBlockConfiguration": {
          "BlockPublicAcls": false,
          "BlockPublicPolicy": false
        }
      }
    },
    "OverpermissivePolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "FullAdminRolePolicy",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"
            }
          ]
        }
      }
    }
  }
}"""


def render_audit_file() -> None:
    apply_theme()

    # 1. Nocturn Page Header
    st.markdown(
        "<h1 style='font-size: 2.3rem; font-weight: 800; color: #ffffff; "
        "margin-bottom: 2px;'>Audit Cloud Files</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='color: #8e90a6; font-size: 0.95rem; margin-bottom: 1.5rem;'>"
        "<b>Shift-Left Security:</b> Audit AWS IAM policies, S3 configurations, and CloudFormation "
        "templates before deploying them to production.</p>",
        unsafe_allow_html=True,
    )

    # 2. Quick-Load Samples Section
    st.markdown(
        "<div style='font-size: 0.85rem; font-weight: 700; color: #a1a1aa; "
        "text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px;'>"
        "🚀 1-Click Interactive Test Samples</div>",
        unsafe_allow_html=True,
    )

    col_s1, col_s2, col_s3, col_s4 = st.columns(4)
    with col_s1:
        if st.button("⚠️ Vulnerable IAM (*)", use_container_width=True):
            st.session_state["pasted_json_input"] = SAMPLE_VULNERABLE_IAM
            _execute_audit(SAMPLE_VULNERABLE_IAM, "Vulnerable-IAM-Policy.json")
    with col_s2:
        if st.button("⚠️ Vulnerable S3 Bucket", use_container_width=True):
            st.session_state["pasted_json_input"] = SAMPLE_VULNERABLE_S3
            _execute_audit(SAMPLE_VULNERABLE_S3, "Vulnerable-S3-Config.json")
    with col_s3:
        if st.button("🔒 Secure IAM Policy", use_container_width=True):
            st.session_state["pasted_json_input"] = SAMPLE_SECURE_IAM
            _execute_audit(SAMPLE_SECURE_IAM, "Secure-IAM-Policy.json")
    with col_s4:
        if st.button("📁 CloudFormation Stack", use_container_width=True):
            st.session_state["pasted_json_input"] = SAMPLE_CLOUDFORMATION
            _execute_audit(SAMPLE_CLOUDFORMATION, "CloudFormation-Stack.json")

    st.write("")

    # 3. Two Input Tabs: File Upload vs Raw Paste
    tab_paste, tab_upload = st.tabs(["📝 Paste Raw JSON Policy", "📁 Drag & Drop File"])

    with tab_paste:
        default_val = st.session_state.get("pasted_json_input", SAMPLE_VULNERABLE_IAM)
        user_text = st.text_area(
            "Paste AWS JSON policy, S3 config, or CloudFormation template:",
            value=default_val,
            height=240,
            help="Paste standard AWS JSON policy or configuration syntax here.",
        )
        if st.button("Audit Pasted Content", type="primary"):
            _execute_audit(user_text, "Pasted-Policy.json")

    with tab_upload:
        uploaded_file = st.file_uploader(
            "Upload AWS JSON Document",
            type=["json"],
            help="Supports IAM policy JSON, S3 configs, CloudFormation, or Columbus exports.",
        )
        if uploaded_file is not None:
            if st.button("Audit Uploaded File", type="primary", key="btn_audit_uploaded"):
                try:
                    file_text = uploaded_file.getvalue().decode("utf-8")
                    _execute_audit(file_text, uploaded_file.name)
                except UnicodeDecodeError:
                    st.error("Uploaded file must be UTF-8 encoded text.")

    # 4. Display Active Audit Results
    active_scan = get_active_scan()
    st.divider()

    st.markdown(
        "<div style='font-size: 1.1rem; font-weight: 700; color: #ffffff; "
        "margin-bottom: 12px;'>📊 Document Audit Verdict</div>",
        unsafe_allow_html=True,
    )

    failures = [f for f in active_scan.findings if f.status == Status.FAIL]
    errors = [f for f in active_scan.findings if f.status == Status.ERROR]

    if failures:
        fail_plural = "s" if len(failures) > 1 else ""
        st.markdown(
            f"""
            <div style="background: rgba(239, 68, 68, 0.12);
                        border: 1px solid rgba(239, 68, 68, 0.4);
                        border-radius: 12px; padding: 16px 20px; margin-bottom: 18px;">
                <div style="font-size: 1.1rem; font-weight: 800; color: #ef4444;">
                    🔴 SECURITY VULNERABILITIES DETECTED ({len(failures)} Failure{fail_plural})
                </div>
                <div style="font-size: 0.88rem; color: #fca5a5; margin-top: 4px;">
                    Violates security baseline rules. Review findings and remediation below.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    elif errors:
        st.markdown(
            """
            <div style="background: rgba(245, 158, 11, 0.12);
                        border: 1px solid rgba(245, 158, 11, 0.4);
                        border-radius: 12px; padding: 16px 20px; margin-bottom: 18px;">
                <div style="font-size: 1.1rem; font-weight: 800; color: #f59e0b;">
                    🟡 UNINSPECTED / VISIBILITY GAPS
                </div>
                <div style="font-size: 0.88rem; color: #fde68a; margin-top: 4px;">
                    Some attributes could not be fully verified against the rule criteria.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style="background: rgba(16, 185, 129, 0.12);
                        border: 1px solid rgba(16, 185, 129, 0.4);
                        border-radius: 12px; padding: 16px 20px; margin-bottom: 18px;">
                <div style="font-size: 1.1rem; font-weight: 800; color: #10b981;">
                    🟢 ALL SECURITY CONTROLS PASSED (100% Posture)
                </div>
                <div style="font-size: 0.88rem; color: #a7f3d0; margin-top: 4px;">
                    No wildcard permissions or public exposure detected. Adheres to baseline.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 5. Render Individual Findings
    for idx, finding in enumerate(active_scan.findings):
        _render_finding_card(finding, idx)


def _render_finding_card(finding: Finding, idx: int) -> None:
    sev_colors = {
        Severity.CRITICAL: "#ef4444",
        Severity.HIGH: "#f97316",
        Severity.MEDIUM: "#eab308",
        Severity.LOW: "#06b6d4",
        Severity.INFORMATIONAL: "#a1a1aa",
    }
    status_badges = {
        Status.FAIL: ("#ef4444", "FAIL"),
        Status.PASS: ("#10b981", "PASS"),
        Status.ERROR: ("#f59e0b", "ERROR"),
        Status.NOT_APPLICABLE: ("#71717a", "N/A"),
    }

    badge_color, badge_text = status_badges.get(finding.status, ("#71717a", finding.status.value))
    sev_color = sev_colors.get(finding.severity, "#a1a1aa")

    with st.expander(
        f"[{badge_text}] {finding.rule_id}: {finding.title} — {finding.resource_id}",
        expanded=(finding.status == Status.FAIL),
    ):
        st.markdown(
            f"""
            <div style="display: flex; gap: 8px; margin-bottom: 12px;">
                <span style="background: rgba(255, 255, 255, 0.08); color: {sev_color};
                             font-size: 0.75rem; font-weight: 700;
                             padding: 2px 10px; border-radius: 6px;">
                    SEVERITY: {finding.severity.value.upper()}
                </span>
                <span style="background: rgba(255, 255, 255, 0.08); color: {badge_color};
                             font-size: 0.75rem; font-weight: 700;
                             padding: 2px 10px; border-radius: 6px;">
                    STATUS: {badge_text}
                </span>
                <span style="background: rgba(255, 255, 255, 0.08); color: #94a3b8;
                             font-size: 0.75rem; padding: 2px 10px; border-radius: 6px;">
                    TYPE: {finding.resource_type}
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(f"**Summary:** {finding.summary}")

        if finding.risk:
            st.markdown(f"**Risk Analysis:** {finding.risk}")

        if finding.remediation:
            st.markdown(f"**Remediation:** {finding.remediation}")

        if finding.evidence:
            st.markdown("**Evidence:**")
            st.json(finding.evidence)


def _execute_audit(content: str, name: str) -> None:
    try:
        with st.spinner(f"Evaluating {name} against security baseline..."):
            scan = run_and_save_content_scan(content, name=name)
        st.success(f"Audit completed: {len(scan.findings)} checks evaluated!")
        st.rerun()
    except FileParseError as exc:
        st.error(f"Parse Error: {exc}")
    except Exception as exc:
        st.error(f"Audit Error: {exc}")
