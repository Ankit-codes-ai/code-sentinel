import streamlit as st
import json
import os
from datetime import datetime
import pandas as pd
import re

st.set_page_config(
    page_title="Code Review Report",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=SF+Pro+Display:wght@300;400;500;600;700&display=swap');
    
    :root {
        --primary-bg: #f5f7fa;
        --secondary-bg: #c3cfe2;
        --card-bg: rgba(255, 255, 255, 0.95);
        --card-border: rgba(255, 255, 255, 0.2);
        --text-primary: #1d1d1f;
        --text-secondary: #8e8e93;
        --highlight-bg: rgba(248, 249, 250, 0.9);
        --code-bg: #f8f9fa;
        --border-light: #e9ecef;
        --content-card-bg: rgba(248, 249, 250, 0.95);
        --content-card-border: rgba(0, 0, 0, 0.1);
    }
    
    @media (prefers-color-scheme: dark) {
        :root {
            --primary-bg: #1a1a1a;
            --secondary-bg: #2d2d30;
            --card-bg: rgba(45, 45, 48, 0.95);
            --card-border: rgba(255, 255, 255, 0.1);
            --text-primary: #ffffff;
            --text-secondary: #a0a0a0;
            --highlight-bg: rgba(45, 45, 48, 0.9);
            --code-bg: #2d2d30;
            --border-light: #404040;
            --content-card-bg: rgba(35, 35, 38, 0.95);
            --content-card-border: rgba(255, 255, 255, 0.1);
        }
    }

    [data-theme="dark"] {
        --primary-bg: #1a1a1a;
        --secondary-bg: #2d2d30;
        --card-bg: rgba(45, 45, 48, 0.95);
        --card-border: rgba(255, 255, 255, 0.1);
        --text-primary: #ffffff;
        --text-secondary: #a0a0a0;
        --highlight-bg: rgba(45, 45, 48, 0.9);
        --code-bg: #2d2d30;
        --border-light: #404040;
        --content-card-bg: rgba(35, 35, 38, 0.95);
        --content-card-border: rgba(255, 255, 255, 0.1);
    }
    
    .stApp {
        background: linear-gradient(135deg, var(--primary-bg) 0%, var(--secondary-bg) 100%);
        font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        color: var(--text-primary);
    }
    
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1200px;
    }
    
    .header-container {
        background: var(--card-bg);
        backdrop-filter: blur(20px);
        border-radius: 20px !important;
        padding: 2rem;
        margin-bottom: 2rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
        border: 1px solid var(--card-border);
    }
    
    .project-title {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.5rem;
    }
    
    .project-subtitle {
        color: var(--text-secondary);
        font-size: 1rem;
        font-weight: 400;
        margin-bottom: 1.5rem;
    }
    
    .metric-display {
        background: var(--card-bg);
        backdrop-filter: blur(20px);
        border-radius: 16px !important;
        padding: 1.5rem;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
        border: 1px solid var(--card-border);
        transition: all 0.3s ease;
        margin-bottom: 1rem;
    }
    
    .metric-display:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.25);
    }
    
    .metric-number {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        display: block;
        color: var(--text-primary);
    }
    
    .metric-label {
        font-size: 0.9rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 0.5rem;
        color: var(--text-secondary);
        white-space: normal;
        word-break: break-word;
        overflow-wrap: break-word;
    }
    
    .severity-critical,
    .severity-high,
    .severity-medium,
    .severity-low {
        padding: 0.3rem 0.8rem;
        border-radius: 20px !important;
        font-weight: 600;
        font-size: 0.8rem;
        display: inline-block;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15);
        max-width: 140px;
        white-space: normal;
        word-break: break-word;
        overflow-wrap: break-word;
        text-overflow: ellipsis;
        text-align: center;
    }
    .severity-critical {
        background: linear-gradient(135deg, #ff6b6b, #ee5a24);
        color: white;
        box-shadow: 0 2px 10px rgba(238, 90, 36, 0.4);
    }
    .severity-high {
        background: linear-gradient(135deg, #ffa726, #ff9800);
        color: white;
        box-shadow: 0 2px 10px rgba(255, 152, 0, 0.4);
    }
    .severity-medium {
        background: linear-gradient(135deg, #42a5f5, #2196f3);
        color: white;
        box-shadow: 0 2px 10px rgba(33, 150, 243, 0.4);
    }
    .severity-low {
        background: linear-gradient(135deg, #66bb6a, #4caf50);
        color: white;
        box-shadow: 0 2px 10px rgba(76, 175, 80, 0.4);
    }
    
    .section-header {
        background: var(--card-bg);
        backdrop-filter: blur(20px);
        border-radius: 12px !important;
        padding: 1rem 1.5rem;
        margin: 1.5rem 0 1rem 0;
        display: flex;
        align-items: center;
        gap: 1rem;
        box-shadow: 0 2px 15px rgba(0, 0, 0, 0.1);
        border: 1px solid var(--card-border);
        flex-wrap: wrap;
    }
    
    .section-title {
        font-size: 1.2rem;
        font-weight: 600;
        margin: 0;
        color: var(--text-primary);
        white-space: normal;
        word-break: break-word;
        overflow-wrap: break-word;
        max-width: 200px;
    }
    
    .section-count {
        background: rgba(103, 126, 234, 0.2);
        color: #667eea;
        padding: 0.2rem 0.6rem;
        border-radius: 12px !important;
        font-size: 0.9rem;
        font-weight: 600;
        white-space: normal;
        word-break: break-word;
        overflow-wrap: break-word;
        max-width: 80px;
        text-align: center;
    }
    
    div[data-testid="stExpander"] {
        background: var(--card-bg) !important;
        backdrop-filter: blur(20px) !important;
        border-radius: 12px !important;
        margin-bottom: 1rem !important;
        box-shadow: 0 2px 15px rgba(0, 0, 0, 0.15) !important;
        border: none !important;
        overflow: hidden !important;
    }
    
    div[data-testid="stExpander"] div[role="button"] {
        background: transparent !important;
        border-radius: 12px 12px 0 0 !important;
        padding: 1rem 1.5rem !important;
        font-weight: 600 !important;
        font-size: 1rem !important;
        color: var(--text-primary) !important;
        transition: all 0.2s ease !important;
        white-space: normal !important;
        word-break: break-word !important;
        overflow-wrap: break-word !important;
        text-overflow: ellipsis !important;
        margin: 0 !important;
        border: none !important;
        box-shadow: none !important;
    }
    
    div[data-testid="stExpander"] div[role="button"]:hover {
        background: rgba(103, 126, 234, 0.1) !important;
        border-radius: 12px 12px 0 0 !important;
    }
    
    div[data-testid="stExpander"] > div > div[data-testid="stExpanderDetails"] {
        padding: 0 1.5rem 1.5rem 1.5rem !important;
        background: transparent !important;
        border: none !important;
        border-radius: 0 0 12px 12px !important;
        color: var(--text-primary) !important;
        margin: 0 !important;
    }
    
    div[data-testid="stExpander"] div,
    div[data-testid="stExpander"] > div,
    div[data-testid="stExpander"] > div > div,
    div[data-testid="stExpander"] * {
        border: none !important;
        box-shadow: none !important;
    }
    
    .content-card {
        background: var(--content-card-bg) !important;
        border-radius: 12px !important;
        padding: 1.5rem;
        margin-bottom: 1rem;
        border-left: 4px solid #667eea;
        color: var(--text-primary) !important;
        border: 1px solid var(--content-card-border) !important;
        border-left: 4px solid #667eea !important;
    }
    
    .security-card {
        background: var(--content-card-bg) !important;
        border-left-color: #ff6b6b !important;
        border: 1px solid var(--content-card-border) !important;
        border-left: 4px solid #ff6b6b !important;
        border-radius: 12px !important;
        color: var(--text-primary) !important;
    }
    
    .issue-card {
        background: var(--content-card-bg) !important;
        border-left-color: #ffa726 !important;
        border: 1px solid var(--content-card-border) !important;
        border-left: 4px solid #ffa726 !important;
        border-radius: 12px !important;
        color: var(--text-primary) !important;
    }
    
    .refactor-card {
        background: var(--content-card-bg) !important;
        border-left-color: #42a5f5 !important;
        border: 1px solid var(--content-card-border) !important;
        border-left: 4px solid #42a5f5 !important;
        border-radius: 12px !important;
        color: var(--text-primary) !important;
    }
    
    .code-snippet {
        background: var(--code-bg);
        border-radius: 8px !important;
        padding: 1rem;
        font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', monospace;
        font-size: 0.9rem;
        border: 1px solid var(--border-light);
        margin: 0.5rem 0;
        color: var(--text-primary);
    }
    
    .file-name {
        background: rgba(103, 126, 234, 0.2);
        color: #667eea;
        padding: 0.2rem 0.6rem;
        border-radius: 8px !important;
        font-family: 'SF Mono', Monaco, monospace;
        font-size: 0.9rem;
        font-weight: 500;
        display: inline-block;
        margin: 2px;
        white-space: normal;
        word-break: break-all;
        overflow-wrap: break-word;
        max-width: 180px;
        text-overflow: ellipsis;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background: var(--card-bg);
        padding: 0.5rem;
        border-radius: 16px !important;
        backdrop-filter: blur(20px);
        margin-bottom: 0 !important; /* KEY FIX: Remove bottom margin */
        border: 1px solid var(--card-border);
    }
    
    .stTabs {
        margin-top: 0 !important;
        margin-bottom: 0 !important;
    }
    
    .stTabs > div {
        margin-top: 0 !important;
        margin-bottom: 0 !important;
        padding-top: 0 !important;
        padding-bottom: 0 !important;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: transparent !important;
        border-radius: 12px !important;
        padding: 0.8rem 1.5rem !important;
        font-weight: 500 !important;
        color: var(--text-secondary) !important;
        border: none !important;
        transition: all 0.3s ease !important;
        white-space: normal !important;
        word-break: break-word !important;
        overflow-wrap: break-word !important;
        max-width: 160px !important;
        text-overflow: ellipsis !important;
        margin: 0 !important;
    }
    
    .stTabs [aria-selected="true"] {
        background: rgba(103, 126, 234, 0.2) !important;
        color: #667eea !important;
        font-weight: 600 !important;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15) !important;
        border-radius: 12px !important;
    }
    
    .stTabs [data-baseweb="tab-panel"] {
        padding-top: 1rem !important;
        margin-top: 0 !important;
    }
    
    hr, 
    .st-emotion-cache-17b7tm, 
    .st-emotion-cache-h5rgaw,
    .st-emotion-cache-1wbqy5l,
    .st-emotion-cache-1jicfl2 {
        display: none !important;
        margin: 0 !important;
        padding: 0 !important;
        height: 0 !important;
    }
    
    footer, #MainMenu, .viewerBadge, header[data-testid="stHeader"] {
        display: none !important;
    }
    
    div[class*="st-emotion-cache"] {
        margin-top: 0 !important;
        margin-bottom: 0 !important;
    }
    
    .element-container + .element-container {
        margin-top: 0 !important;
    }
    
    .cwe-badge {
        background: rgba(142, 142, 147, 0.2) !important;
        color: var(--text-secondary) !important;
        padding: 0.2rem 0.6rem !important;
        border-radius: 8px !important;
        font-size: 0.8rem !important;
        font-weight: 500 !important;
        margin-left: 0.5rem !important;
        display: inline-block !important;
        white-space: normal !important;
        word-break: break-word !important;
        overflow-wrap: break-word !important;
        max-width: 120px !important;
        text-overflow: ellipsis !important;
        border: 1px solid var(--border-light) !important;
    }
    
    .critical-metric { color: #ff6b6b; }
    .high-metric { color: #ffa726; }
    .medium-metric { color: #42a5f5; }
    .low-metric { color: #66bb6a; }
    
    .highlight-box {
        background: var(--content-card-bg) !important;
        border-radius: 8px !important;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 3px solid #667eea;
        white-space: normal;
        word-break: break-word;
        overflow-wrap: break-word;
        color: var(--text-primary) !important;
        border: 1px solid var(--content-card-border) !important;
        border-left: 3px solid #667eea !important;
    }
    
    .cvss-high { color: #ff6b6b; font-weight: 700; }
    .cvss-medium { color: #ffa726; font-weight: 700; }
    .cvss-low { color: #66bb6a; font-weight: 700; }
    
    .effort-small { color: #66bb6a; font-weight: 600; }
    .effort-medium { color: #ffa726; font-weight: 600; }
    .effort-large { color: #ff6b6b; font-weight: 600; }
    
    .file-list {
        background: var(--content-card-bg) !important;
        border-radius: 8px !important;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 3px solid #667eea;
        white-space: normal;
        word-break: break-word;
        overflow-wrap: break-word;
        color: var(--text-primary) !important;
        border: 1px solid var(--content-card-border) !important;
        border-left: 3px solid #667eea !important;
    }
    
    .dependencies-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
        gap: 0.5rem;
        margin: 1rem 0;
        white-space: normal;
        word-break: break-word;
        overflow-wrap: break-word;
    }
    
    p, div, span, strong, em {
        color: var(--text-primary);
    }
    
    .stMarkdown, .stMarkdown p, .stMarkdown div, .stMarkdown span {
        color: var(--text-primary) !important;
    }
    
    .stCode, pre, code {
        background: var(--code-bg) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-light) !important;
        border-radius: 8px !important;
    }
    
    [data-testid="stMarkdownContainer"] * {
        color: var(--text-primary) !important;
    }
    
    .stTabs > div,
    .stTabs > div > div,
    [data-baseweb="tab-list"],
    [data-baseweb="tab-list"] > div,
    [data-baseweb="tab"] {
        border-radius: 12px !important;
    }
    
    div[data-testid="stExpander"],
    div[data-testid="stExpander"] *,
    .content-card,
    .security-card,
    .issue-card,
    .refactor-card,
    .highlight-box,
    .file-list {
        outline: none !important;
    }
</style>
""", unsafe_allow_html=True)


def load_report_data(json_file):
    with open(json_file, 'r') as f:
        return json.load(f)


def get_severity_class(severity):
    severity = severity.split(".")[-1].lower()
    return f"severity-{severity}"


def display_header(report_data):
    project_name = report_data.get('project_name', 'Project Review')
    timestamp = report_data.get('timestamp', datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))
    try:
        original_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        original_fmt = original_dt.strftime('%B %d, %Y at %H:%M')
        if original_dt.tzinfo is not None:
            original_fmt += f" {original_dt.tzname() or 'UTC'}"
    except Exception:
        original_fmt = timestamp

    generated_fmt = datetime.now().strftime('%B %d, %Y at %H:%M')

    st.markdown(f"""
    <div class='header-container'>
        <h1 class='project-title'>{project_name}</h1>
        <p class='project-subtitle'>Generated: {generated_fmt} &bull; Original Analysis: {original_fmt}</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"""
        <div class='metric-display'>
            <span class='metric-number'>{report_data['total_files_reviewed']}</span>
            <span class='metric-label'>Files Reviewed</span>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class='metric-display'>
            <span class='metric-number'>{report_data['total_lines_of_code']:,}</span>
            <span class='metric-label'>Lines of Code</span>
        </div>
        """, unsafe_allow_html=True)


def display_summary_metrics(report_data):
    security_findings = report_data['security_findings']
    issues = report_data['issues']
    
    severity_counts = {
        "CRITICAL": len([i for i in security_findings if i['severity'] == "ReviewSeverity.CRITICAL"]),
        "HIGH": len([i for i in security_findings if i['severity'] == "ReviewSeverity.HIGH"] + 
                   [i for i in issues if i['severity'] == "ReviewSeverity.HIGH"]),
        "MEDIUM": len([i for i in security_findings if i['severity'] == "ReviewSeverity.MEDIUM"] + 
                     [i for i in issues if i['severity'] == "ReviewSeverity.MEDIUM"]),
        "LOW": len([i for i in security_findings if i['severity'] == "ReviewSeverity.LOW"] + 
                  [i for i in issues if i['severity'] == "ReviewSeverity.LOW"])
    }
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class='metric-display'>
            <span class='metric-number critical-metric'>{severity_counts['CRITICAL']}</span>
            <span class='metric-label'>Critical Issues</span>
            <div class='severity-critical'>CRITICAL</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class='metric-display'>
            <span class='metric-number high-metric'>{severity_counts['HIGH']}</span>
            <span class='metric-label'>High Priority</span>
            <div class='severity-high'>HIGH</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class='metric-display'>
            <span class='metric-number medium-metric'>{severity_counts['MEDIUM']}</span>
            <span class='metric-label'>Medium Priority</span>
            <div class='severity-medium'>MEDIUM</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class='metric-display'>
            <span class='metric-number low-metric'>{severity_counts['LOW']}</span>
            <span class='metric-label'>Low Priority</span>
            <div class='severity-low'>LOW</div>
        </div>
        """, unsafe_allow_html=True)


def _normalize_severity(value: str) -> str:
    """Return canonical severity name (CRITICAL/HIGH/MEDIUM/LOW) from any variant."""
    if not value:
        return "LOW"
    return value.split(".")[-1].strip().upper()

def _render_inline_md(text: str) -> str:
    """Convert minimal inline markdown (**bold** / __bold__) to corresponding HTML."""
    if not text:
        return ""
    text = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"__(.*?)__", r"<strong>\1</strong>", text)
    return text


def display_security_findings(security_findings):
    if not security_findings:
        st.info("No security findings were detected in this review.")
        return

    buckets = {s: [] for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    for finding in security_findings:
        sev = _normalize_severity(finding.get("severity", ""))
        buckets.setdefault(sev, []).append(finding)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for severity in severity_order:
        findings = buckets.get(severity, [])
        if findings:
            severity_name = severity
            severity_class = get_severity_class(f"ReviewSeverity.{severity}")
            
            st.markdown(f"""
            <div class='section-header'>
                <span class='{severity_class}'>{severity_name}</span>
                <span class='section-title'>Security Findings</span>
                <span class='section-count'>{len(findings)}</span>
            </div>
            """, unsafe_allow_html=True)
            
            for finding in findings:
                cwe_id = finding.get('cwe_id', '')
                cwe_display = f" {cwe_id}" if cwe_id else ""
                
                with st.expander(f"🔒 {finding['vulnerability_type']}{cwe_display}", expanded=False):
                    if cwe_id:
                        st.markdown(f"<span class='cwe-badge'>{cwe_id}</span>", unsafe_allow_html=True)
                    
                    st.markdown("**📋 Description**")
                    st.markdown(f"""
                    <div class='content-card security-card'>
                        {finding['description']}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("**⚔️ Attack Vector**")
                    st.markdown(f"""
                    <div class='content-card security-card'>
                        {finding['attack_vector']}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("**🛡️ Mitigation**")
                    mitigation_text = format_mitigation_text(finding['mitigation'])
                    st.markdown(f"""
                    <div class='content-card security-card'>
                        {mitigation_text}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    score_val = finding.get('cvss_score')
                    if score_val is not None:
                        try:
                            cvss = float(score_val)
                            cvss_class = (
                                "cvss-high" if cvss >= 7.0 else
                                "cvss-medium" if cvss >= 4.0 else
                                "cvss-low"
                            )
                            st.markdown(
                                f"**CVSS Score:** <span class='{cvss_class}'>{cvss}</span>",
                                unsafe_allow_html=True
                            )
                        except (ValueError, TypeError):
                            st.markdown(f"**CVSS Score:** {score_val}")
                    
                    if finding.get('affected_files'):
                        st.markdown("**📁 Affected Files:**")
                        files_html = "<div class='file-list'>"
                        for file in finding['affected_files']:
                            files_html += f"<span class='file-name'>{os.path.basename(file)}</span> "
                        files_html += "</div>"
                        st.markdown(files_html, unsafe_allow_html=True)


def display_issues(issues):
    """Render the Code Issues tab, showing placeholder when empty."""
    if not issues:
        st.info("No code issues were detected in this review.")
        return

    buckets = {s: [] for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    for issue in issues:
        sev = _normalize_severity(issue.get("severity", ""))
        buckets.setdefault(sev, []).append(issue)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for severity in severity_order:
        issues_list = buckets.get(severity, [])
        if issues_list:
            severity_name = severity
            severity_class = get_severity_class(f"ReviewSeverity.{severity}")
            
            st.markdown(f"""
            <div class='section-header'>
                <span class='{severity_class}'>{severity_name}</span>
                <span class='section-title'>Code Issues</span>
                <span class='section-count'>{len(issues_list)}</span>
            </div>
            """, unsafe_allow_html=True)
            
            for issue in issues_list:
                with st.expander(f"⚠️ {issue['title']}", expanded=False):
                    st.markdown("**📋 Description**")
                    st.markdown(f"""
                    <div class='content-card issue-card'>
                        {issue['description']}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("**💡 Recommendation**")
                    st.markdown(f"""
                    <div class='content-card issue-card'>
                        {issue['recommendation']}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    if issue.get('file_path') and issue['file_path'] != "multiple":
                        file_name = os.path.basename(issue['file_path'])
                        st.markdown(f"**📄 File:** <span class='file-name'>{file_name}</span>", unsafe_allow_html=True)
                    
                    if issue.get('line_number'):
                        st.markdown(f"**📍 Line:** {issue['line_number']}")
                    
                    if issue.get('code_snippet'):
                        st.markdown("**💻 Code Snippet:**")
                        st.code(issue['code_snippet'], language="python")


def display_refactoring(refactoring_recommendations):
    if not refactoring_recommendations:
        return
    
    st.markdown(f"""
    <div class='section-header'>
        <span class='severity-medium'>REFACTORING</span>
        <span class='section-title'>Recommendations</span>
        <span class='section-count'>{len(refactoring_recommendations)}</span>
    </div>
    """, unsafe_allow_html=True)
    
    for item in refactoring_recommendations:
        description_preview = item['description'][:80] + ('...' if len(item['description']) > 80 else '')
        
        with st.expander(f"🔄 {description_preview}", expanded=False):
            st.markdown("**📋 Description**")
            st.markdown(f"""
            <div class='content-card refactor-card'>
                {item['description']}
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("**🎯 Rationale**")
            st.markdown(f"""
            <div class='content-card refactor-card'>
                {item['rationale']}
            </div>
            """, unsafe_allow_html=True)
            
            effort = item.get('estimated_effort', 'medium').lower()
            effort_class = f"effort-{effort}"
            st.markdown(f"**⏱️ Estimated Effort:** <span class='{effort_class}'>{effort.upper()}</span>", unsafe_allow_html=True)
            
            target_files = item.get('target_files', [])
            if target_files:
                st.markdown("**📁 Target Files:**")
                files_html = "<div class='file-list'>"
                for file in target_files:
                    file_name = os.path.basename(file)
                    files_html += f"<span class='file-name'>{file_name}</span> "
                files_html += "</div>"
                st.markdown(files_html, unsafe_allow_html=True)


def display_dependency_analysis(dependency_analysis):
    st.markdown(f"""
    <div class='section-header'>
        <span class='severity-medium'>DEPENDENCIES</span>
        <span class='section-title'>Analysis</span>
    </div>
    """, unsafe_allow_html=True)

    if not dependency_analysis:
        st.info("No dependency analysis information provided in the report.")
        return

    if not any(
        dependency_analysis.get(k) for k in [
            'external_dependencies',
            'outdated_dependencies',
            'vulnerability_scan'
        ]
    ):
        st.info("No dependency issues or external libraries detected.")
        return
    
    if dependency_analysis.get('external_dependencies'):
        with st.expander("📦 External Dependencies", expanded=False):
            deps = dependency_analysis['external_dependencies']
            
            st.markdown("**External Dependencies Found:**")
            deps_html = "<div class='content-card'><div class='dependencies-grid'>"
            for dep in deps:
                deps_html += f"<span class='file-name'>{dep}</span>"
            deps_html += "</div></div>"
            st.markdown(deps_html, unsafe_allow_html=True)
    
    if dependency_analysis.get('outdated_dependencies'):
        with st.expander("⚠️ Outdated Dependencies", expanded=False):
            for dep in dependency_analysis['outdated_dependencies']:
                issue_type = dep['issue']
                
                st.markdown(f"**📦 {dep['name']} - {issue_type.upper()}**")
                st.markdown(f"""
                <div class='content-card issue-card'>
                    <strong>Concern:</strong> {dep['current_concern']}<br>
                    <strong>Recommendation:</strong> {dep['recommendation']}
                </div>
                """, unsafe_allow_html=True)
    
    if dependency_analysis.get('vulnerability_scan'):
        with st.expander("🔒 Dependency Vulnerabilities", expanded=False):
            for vuln in dependency_analysis['vulnerability_scan']:
                severity_class = get_severity_class(vuln.get('severity', 'ReviewSeverity.MEDIUM'))
                severity_name = vuln.get('severity', 'ReviewSeverity.MEDIUM').split('.')[-1]
                cwe_id = vuln.get('cwe_id', '')
                cwe_display = f" {cwe_id}" if cwe_id else ""
                
                st.markdown(f"**🔒 {vuln['vulnerability_type']}{cwe_display}**")
                if cwe_id:
                    st.markdown(f"<span class='cwe-badge'>{cwe_id}</span>", unsafe_allow_html=True)
                
                mitigation_text = format_mitigation_text(vuln['mitigation'])
                st.markdown(f"""
                <div class='content-card security-card'>
                    <strong>Severity:</strong> <span class='{severity_class}'>{severity_name}</span><br>
                    <strong>Description:</strong> {vuln['description']}<br>
                    <strong>Attack Vector:</strong> {vuln['attack_vector']}<br>
                    <strong>Mitigation:</strong> {mitigation_text}
                </div>
                """, unsafe_allow_html=True)
                
                score_val = vuln.get('cvss_score')
                if score_val is not None:
                    try:
                        cvss = float(score_val)
                        cvss_class = (
                            "cvss-high" if cvss >= 7.0 else
                            "cvss-medium" if cvss >= 4.0 else
                            "cvss-low"
                        )
                        st.markdown(
                            f"**CVSS Score:** <span class='{cvss_class}'>{cvss}</span>",
                            unsafe_allow_html=True
                        )
                    except (ValueError, TypeError):
                        st.markdown(f"**CVSS Score:** {score_val}")


def display_control_flow(control_flow_analysis):
    st.markdown(f"""
    <div class='section-header'>
        <span class='severity-medium'>FLOW</span>
        <span class='section-title'>Analysis</span>
    </div>
    """, unsafe_allow_html=True)

    keys_of_interest = [
        'entry_points',
        'data_flow_patterns',
        'control_dependencies',
        'potential_bottlenecks',
        'error_handling_patterns',
        'complexity_hotspots'
    ]
    if not any(control_flow_analysis.get(k) for k in keys_of_interest):
        st.info("No control-flow analysis details were provided in the report.")
        return
    
    if control_flow_analysis.get('entry_points'):
        with st.expander("🚪 Entry Points", expanded=False):
            entry_html = '<div class="content-card">'
            for point in control_flow_analysis['entry_points']:
                file_name = os.path.basename(point)
                entry_html += f"• <span class='file-name'>{file_name}</span><br>"
            entry_html += '</div>'
            st.markdown(entry_html, unsafe_allow_html=True)
    
    if control_flow_analysis.get('data_flow_patterns'):
        with st.expander("🔄 Data Flow Patterns", expanded=False):
            flow_html = '<div class="content-card">'
            for pattern in control_flow_analysis['data_flow_patterns']:
                flow_html += f"• {_render_inline_md(pattern)}<br>"
            flow_html += '</div>'
            st.markdown(flow_html, unsafe_allow_html=True)
    
    if control_flow_analysis.get('potential_bottlenecks'):
        with st.expander("🚧 Potential Bottlenecks", expanded=False):
            for i, bottleneck in enumerate(control_flow_analysis['potential_bottlenecks']):
                highlighted_text = bottleneck
                for potential_file in ["review-caller.py", "report-generator.py", "packager.py"]:
                    if potential_file in bottleneck:
                        highlighted_text = bottleneck.replace(
                            potential_file, 
                            f"<span class='file-name'>{potential_file}</span>"
                        )
                
                st.markdown(f"""
                <div class='highlight-box'>
                    <strong>Bottleneck {i+1}:</strong> {_render_inline_md(highlighted_text)}
                </div>
                """, unsafe_allow_html=True)
    
    if control_flow_analysis.get('error_handling_patterns'):
        with st.expander("🛡️ Error Handling Patterns", expanded=False):
            error_html = '<div class="content-card">'
            for pattern in control_flow_analysis['error_handling_patterns']:
                error_html += f"• {_render_inline_md(pattern)}<br>"
            error_html += '</div>'
            st.markdown(error_html, unsafe_allow_html=True)
    
    if control_flow_analysis.get('complexity_hotspots'):
        with st.expander("🔥 Complexity Hotspots", expanded=False):
            for i, hotspot in enumerate(control_flow_analysis['complexity_hotspots']):
                highlighted_text = hotspot
                for potential_file in ["review-caller.py", "report-generator.py", "packager.py"]:
                    if potential_file in hotspot:
                        highlighted_text = hotspot.replace(
                            potential_file, 
                            f"<span class='file-name'>{potential_file}</span>"
                        )
                
                st.markdown(f"""
                <div class='highlight-box'>
                    <strong>Hotspot {i+1}:</strong> {_render_inline_md(highlighted_text)}
                </div>
                """, unsafe_allow_html=True)


def format_mitigation_text(text):
    import re
    text = re.sub(r'(\d+\.)(?!\s)', r'\1 ', text)
    numbered = re.split(r'(\d+\.\s)', text)
    if len(numbered) > 1:
        result = ''
        for i in range(1, len(numbered), 2):
            if i > 1:
                result += '<br>'
            result += numbered[i] + numbered[i+1]
        return result.strip()
    return text.replace('\n', '<br>')

def main():
    hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
    """
    st.markdown(hide_streamlit_style, unsafe_allow_html=True)
    
    json_file_path = os.path.join(os.path.dirname(__file__), "review_report.json")
    
    if os.path.exists(json_file_path):
        try:
            report_data = load_report_data(json_file_path)
            
            display_header(report_data)
            display_summary_metrics(report_data)
            
            tab1, tab2, tab3, tab4 = st.tabs(["Security Findings", "Code Issues", "Refactoring", "Analysis"])
            
            with tab1:
                display_security_findings(report_data['security_findings'])
                
            with tab2:
                display_issues(report_data['issues'])
                
            with tab3:
                display_refactoring(report_data.get('refactoring_recommendations', []))
                
            with tab4:
                col1, col2 = st.columns(2)
                
                with col1:
                    display_dependency_analysis(report_data.get('dependency_analysis', {}))
                    
                with col2:
                    display_control_flow(report_data.get('control_flow_analysis', {}))
        except Exception as e:
            st.error(f"Error loading or displaying the report: {str(e)}")
    else:
        st.error(f"Report file not found: {json_file_path}. Please ensure the file exists in the same directory as this script.")


if __name__ == "__main__":
    main()