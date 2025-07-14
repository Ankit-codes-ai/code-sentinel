import json
import os
from datetime import datetime
import google.generativeai as genai
import urllib.request
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.units import inch
from reportlab.platypus.flowables import HRFlowable
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.fonts import addMapping

GOOGLE_API_KEY = os.environ.get('GEMINI_API_KEY', '')
if not GOOGLE_API_KEY:
    print("ERROR: No Gemini API key provided. Set the GEMINI_API_KEY environment variable.")
else:
    genai.configure(api_key=GOOGLE_API_KEY)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FONT_DIR = os.path.join(SCRIPT_DIR, "fonts")

def register_fonts():
    """Register 'SF-Pro' font from the local 'fonts' directory."""
    try:
        font_file_path = os.path.join(FONT_DIR, 'SF-Pro.ttf')
        if not os.path.exists(font_file_path):
            print(f"ERROR: Font 'SF-Pro.ttf' not found in '{FONT_DIR}'.")
            print("Please ensure the font file is in the 'review-caller/fonts' directory.")
            return 'Helvetica'

        pdfmetrics.registerFont(TTFont('SF-Pro', font_file_path))
        addMapping('SF-Pro', 0, 0, 'SF-Pro')
        addMapping('SF-Pro', 1, 0, 'SF-Pro')
        addMapping('SF-Pro', 0, 1, 'SF-Pro')
        addMapping('SF-Pro', 1, 1, 'SF-Pro')
        
        print("Successfully registered 'SF-Pro' font.")
        return 'SF-Pro'
    except Exception as e:
        print(f"Warning: Could not register 'SF-Pro' font ({e}). Using default 'Helvetica'.")
        return 'Helvetica'

def load_report_data(json_file):
    """Load the JSON report data from file"""
    with open(json_file, 'r') as f:
        return json.load(f)

def get_severity_color(severity):
    """Return color based on severity level but with more professional colors"""
    severity_map = {
        "ReviewSeverity.CRITICAL": colors.HexColor('#d9534f'),
        "ReviewSeverity.HIGH": colors.HexColor('#f0ad4e'),
        "ReviewSeverity.MEDIUM": colors.HexColor('#5bc0de'),
        "ReviewSeverity.LOW": colors.HexColor('#5cb85c'),
    }
    return severity_map.get(severity, colors.black)

def create_styles(font_name):
    """Create professional document styles"""
    styles = getSampleStyleSheet()
    
    styles['Normal'].fontName = font_name
    styles['Normal'].fontSize = 10
    styles['Normal'].leading = 14
    
    styles['Heading1'].fontName = font_name
    styles['Heading1'].fontSize = 18
    styles['Heading1'].leading = 22
    styles['Heading1'].spaceAfter = 12
    styles['Heading1'].spaceBefore = 12
    
    styles['Heading2'].fontName = font_name
    styles['Heading2'].fontSize = 14
    styles['Heading2'].leading = 18
    styles['Heading2'].spaceAfter = 6
    styles['Heading2'].spaceBefore = 10
    
    styles['Heading3'].fontName = font_name
    styles['Heading3'].fontSize = 12
    styles['Heading3'].leading = 14
    styles['Heading3'].spaceAfter = 4
    styles['Heading3'].spaceBefore = 8
    
    if 'Emphasis' not in styles.byName:
        styles.add(
            ParagraphStyle(
                name='Emphasis',
                parent=styles['Normal'],
                fontName=font_name,
            )
        )
    
    if 'Bullet' not in styles.byName:
        styles.add(
            ParagraphStyle(
                name='Bullet',
                parent=styles['Normal'],
                leftIndent=36,
                firstLineIndent=0,
                spaceBefore=3
            )
        )

    if 'Code' not in styles.byName:
        styles.add(
            ParagraphStyle(
                name='Code',
                parent=styles['Normal'],
                fontName='Courier',
                fontSize=8,
                leading=10,
                firstLineIndent=0,
                leftIndent=36
            )
        )
    
    if 'CustomTitle' not in styles.byName:
        styles.add(
            ParagraphStyle(
                name='CustomTitle',
                parent=styles['Title'],
                fontName=font_name,
                fontSize=24,
                spaceAfter=12,
                leading=30,
                alignment=1
            )
        )
    
    return styles

def create_title(doc, report_data, styles):
    """Create the title section of the report"""
    elements = []
    
    elements.append(Paragraph(f"<b>{report_data['project_name']}</b>", styles["CustomTitle"]))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
    elements.append(Paragraph(f"Original Analysis: {report_data['timestamp']}", styles["Normal"]))
    elements.append(Spacer(1, 0.2*inch))
    elements.append(Paragraph(f"<b>Summary:</b> {report_data['summary']}", styles["Normal"]))
    elements.append(Spacer(1, 0.2*inch))
    
    elements.append(Paragraph("<b>Project Metrics</b>", styles["Heading2"]))
    elements.append(Paragraph(f"Total Files Reviewed: {report_data['total_files_reviewed']}", styles["Normal"]))
    elements.append(Paragraph(f"Total Lines of Code: {report_data['total_lines_of_code']}", styles["Normal"]))
    elements.append(Spacer(1, 0.3*inch))
    
    return elements

def format_ai_summary(summary_text, styles):
    """Formats markdown-like text from Gemini into ReportLab flowables."""
    elements = []
    
    for line in summary_text.split('\n'):
        original_line = line.strip()
        if not original_line:
            continue

        parts = original_line.split('**')
        processed_line = "".join([f"<b>{part}</b>" if i % 2 else part for i, part in enumerate(parts)])

        if original_line.startswith('### '):
            clean_line = processed_line.replace('### ', '', 1)
            elements.append(Paragraph(clean_line, styles["Heading2"]))
            elements.append(Spacer(1, 0.1 * inch))
        elif original_line.startswith('**') and original_line.endswith('**'):
            elements.append(Paragraph(processed_line, styles["Heading2"]))
            elements.append(Spacer(1, 0.1 * inch))
        elif original_line.startswith('* ') or original_line.startswith('- '):
            clean_line = processed_line[2:]
            elements.append(Paragraph(f"• {clean_line}", styles["Bullet"]))
        elif len(original_line) > 2 and original_line[0].isdigit() and original_line[1] == '.':
             elements.append(Paragraph(processed_line, styles["Bullet"]))
        else:
            elements.append(Paragraph(processed_line, styles["Normal"]))
            elements.append(Spacer(1, 0.05 * inch))

    return elements

def create_executive_summary(doc, report_data, styles):
    """Create an AI-generated executive summary for the main report."""
    elements = []
    
    elements.append(Paragraph("<b>EXECUTIVE SUMMARY</b>", styles["Heading1"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.2*inch))

    print("Generating AI summary for the main report...")
    summary_text = generate_summary_with_gemini(report_data)
    
    if "Error generating AI summary" in summary_text:
        elements.append(Paragraph(summary_text, styles["Normal"]))
    else:
        elements.extend(format_ai_summary(summary_text, styles))

    elements.append(PageBreak())
    return elements

def create_issues_section(doc, report_data, styles):
    """Create the issues section"""
    elements = []
    
    elements.append(Paragraph("<b>DETAILED ISSUES</b>", styles["Heading1"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.2*inch))
    
    severity_order = ["ReviewSeverity.CRITICAL", "ReviewSeverity.HIGH", "ReviewSeverity.MEDIUM", "ReviewSeverity.LOW"]
    for severity in severity_order:
        issues = [issue for issue in report_data['issues'] if issue['severity'] == severity]
        if issues:
            severity_name = severity.split('.')[-1]
            elements.append(Paragraph(f"<b>{severity_name} Severity Issues</b>", styles["Heading2"]))
            
            for i, issue in enumerate(issues, 1):
                color = get_severity_color(issue['severity'])
                elements.append(Paragraph(f"<font color='{color.hexval()}'><b>{i}. {issue['title']}</b></font>", styles["Heading3"]))
                elements.append(Paragraph(f"<b>Description:</b> {issue['description']}", styles["Normal"]))
                elements.append(Paragraph(f"<b>Recommendation:</b> {issue['recommendation']}", styles["Normal"]))
                
                if issue['file_path'] and issue['file_path'] != "multiple":
                    elements.append(Paragraph(f"<b>File:</b> {issue['file_path']}", styles["Normal"]))
                
                if issue['line_number']:
                    elements.append(Paragraph(f"<b>Line:</b> {issue['line_number']}", styles["Normal"]))
                
                if issue['code_snippet']:
                    elements.append(Paragraph("<b>Code Snippet:</b>", styles["Normal"]))
                    elements.append(Paragraph(f"<pre>{issue['code_snippet']}</pre>", styles['Code']))
                    
                elements.append(Spacer(1, 0.2*inch))
    
    elements.append(PageBreak())
    return elements

def create_security_section(doc, report_data, styles):
    """Create the security findings section"""
    elements = []
    
    elements.append(Paragraph("<b>SECURITY FINDINGS</b>", styles["Heading1"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.2*inch))
    
    severity_order = ["ReviewSeverity.CRITICAL", "ReviewSeverity.HIGH", "ReviewSeverity.MEDIUM", "ReviewSeverity.LOW"]
    for severity in severity_order:
        findings = [finding for finding in report_data['security_findings'] if finding['severity'] == severity]
        if findings:
            severity_name = severity.split('.')[-1]
            elements.append(Paragraph(f"<b>{severity_name} Severity Security Findings</b>", styles["Heading2"]))
            
            for i, finding in enumerate(findings, 1):
                color = get_severity_color(finding['severity'])
                elements.append(Paragraph(f"<font color='{color.hexval()}'><b>{i}. {finding['vulnerability_type']} ({finding['cwe_id']})</b></font>", styles["Heading3"]))
                elements.append(Paragraph(f"<b>Description:</b> {finding['description']}", styles["Normal"]))
                elements.append(Paragraph(f"<b>Attack Vector:</b> {finding['attack_vector']}", styles["Normal"]))
                elements.append(Paragraph(f"<b>Mitigation:</b> {finding['mitigation']}", styles["Normal"]))
                elements.append(Paragraph(f"<b>CVSS Score:</b> {finding['cvss_score']}", styles["Normal"]))
                
                if finding['affected_files']:
                    elements.append(Paragraph("<b>Affected Files:</b>", styles["Normal"]))
                    for file in finding['affected_files']:
                        elements.append(Paragraph(f"- {file}", styles["Normal"]))
                
                elements.append(Spacer(1, 0.2*inch))
    
    elements.append(PageBreak())
    return elements

def create_refactoring_section(doc, report_data, styles):
    """Create the refactoring recommendations section."""
    elements = []

    if not report_data.get('refactoring_recommendations'):
        return elements
        
    elements.append(Paragraph("<b>REFACTORING RECOMMENDATIONS</b>", styles["Heading1"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.2 * inch))

    for item in report_data['refactoring_recommendations']:
        elements.append(Paragraph(f"<b>{item['description']}</b>", styles["Heading3"]))
        elements.append(Paragraph(f"<b>Rationale:</b> {item['rationale']}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Estimated Effort:</b> {item['estimated_effort']}", styles["Normal"]))
        
        target_files = ", ".join(item['target_files'])
        elements.append(Paragraph(f"<b>Target Files:</b> {target_files}", styles["Normal"]))
        elements.append(Spacer(1, 0.2*inch))
        
    elements.append(PageBreak())
    return elements

def create_dependency_section(doc, report_data, styles):
    """Create the dependency analysis section"""
    elements = []
    
    elements.append(Paragraph("<b>DEPENDENCY ANALYSIS</b>", styles["Heading1"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.2*inch))
    
    if report_data['dependency_analysis']['external_dependencies']:
        elements.append(Paragraph("<b>External Dependencies</b>", styles["Heading2"]))
        deps = report_data['dependency_analysis']['external_dependencies']
        for dep in deps:
            elements.append(Paragraph(f"- {dep}", styles["Normal"]))
        elements.append(Spacer(1, 0.2*inch))
    
    if report_data['dependency_analysis']['outdated_dependencies']:
        elements.append(Paragraph("<b>Outdated Dependencies</b>", styles["Heading2"]))
        deps = report_data['dependency_analysis']['outdated_dependencies']
        for dep in deps:
            elements.append(Paragraph(f"<b>{dep['name']}</b>", styles["Heading3"]))
            elements.append(Paragraph(f"<b>Issue:</b> {dep['issue']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>Concern:</b> {dep['current_concern']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>Recommendation:</b> {dep['recommendation']}", styles["Normal"]))
            elements.append(Spacer(1, 0.1*inch))
    
    if report_data['dependency_analysis']['vulnerability_scan']:
        elements.append(Paragraph("<b>Vulnerability Scan</b>", styles["Heading2"]))
        vulns = report_data['dependency_analysis']['vulnerability_scan']
        for vuln in vulns:
            color = get_severity_color(vuln['severity'])
            elements.append(Paragraph(f"<font color='{color.hexval()}'><b>{vuln['vulnerability_type']} (Severity: {vuln['severity'].split('.')[-1]})</b></font>", styles["Heading3"]))
            elements.append(Paragraph(f"<b>Description:</b> {vuln['description']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>Attack Vector:</b> {vuln['attack_vector']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>Mitigation:</b> {vuln['mitigation']}", styles["Normal"]))
            elements.append(Paragraph(f"<b>CVSS Score:</b> {vuln['cvss_score']}", styles["Normal"]))
            elements.append(Spacer(1, 0.1*inch))
    
    elements.append(PageBreak())
    return elements

def create_control_flow_section(doc, report_data, styles):
    """Create the control flow analysis section"""
    elements = []
    
    elements.append(Paragraph("<b>CONTROL FLOW ANALYSIS</b>", styles["Heading1"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 0.2*inch))
    
    flow_data = report_data['control_flow_analysis']
    
    if flow_data['entry_points']:
        elements.append(Paragraph("<b>Entry Points</b>", styles["Heading2"]))
        for point in flow_data['entry_points']:
            elements.append(Paragraph(f"- {point}", styles["Normal"]))
        elements.append(Spacer(1, 0.2*inch))
    
    if flow_data['data_flow_patterns']:
        elements.append(Paragraph("<b>Data Flow Patterns</b>", styles["Heading2"]))
        for pattern in flow_data['data_flow_patterns']:
            elements.append(Paragraph(f"- {pattern}", styles["Normal"]))
        elements.append(Spacer(1, 0.2*inch))
    
    if flow_data['potential_bottlenecks']:
        elements.append(Paragraph("<b>Potential Bottlenecks</b>", styles["Heading2"]))
        for bottleneck in flow_data['potential_bottlenecks']:
            elements.append(Paragraph(f"- {bottleneck}", styles["Normal"]))
        elements.append(Spacer(1, 0.2*inch))
    
    if flow_data['error_handling_patterns']:
        elements.append(Paragraph("<b>Error Handling Patterns</b>", styles["Heading2"]))
        for pattern in flow_data['error_handling_patterns']:
            elements.append(Paragraph(f"- {pattern}", styles["Normal"]))
        elements.append(Spacer(1, 0.2*inch))
    
    if flow_data['complexity_hotspots']:
        elements.append(Paragraph("<b>Complexity Hotspots</b>", styles["Heading2"]))
        for hotspot in flow_data['complexity_hotspots']:
            elements.append(Paragraph(f"- {hotspot}", styles["Normal"]))
        elements.append(Spacer(1, 0.2*inch))
    
    return elements

def generate_summary_with_gemini(report_data):
    """Generate a concise summary of the report using Google Gemini"""
    
    high_security = [item for item in report_data['security_findings'] 
                    if item['severity'] in ["ReviewSeverity.CRITICAL", "ReviewSeverity.HIGH"]]
    
    high_issues = [item for item in report_data['issues'] 
                  if item['severity'] in ["ReviewSeverity.CRITICAL", "ReviewSeverity.HIGH"]]
    
    refactoring_recs = report_data['refactoring_recommendations']
    
    prompt = f"""
    Summarize the following code review information into a VERY concise executive summary (less than 500 words total).
    Focus on the most critical issues and provide actionable recommendations. Be professional, direct, and concise.
    
    Project: {report_data['project_name']}
    Files Reviewed: {report_data['total_files_reviewed']}
    Lines of Code: {report_data['total_lines_of_code']}
    
    ### High Severity Security Findings ({len(high_security)})
    {json.dumps([{
        'type': item['vulnerability_type'],
        'description': item['description'],
        'mitigation': item['mitigation']
    } for item in high_security], indent=2)}
    
    ### High Severity Issues ({len(high_issues)})
    {json.dumps([{
        'title': item['title'],
        'description': item['description'],
        'recommendation': item['recommendation']
    } for item in high_issues], indent=2)}
    
    ### Key Refactoring Recommendations ({len(refactoring_recs)})
    {json.dumps([{
        'description': item['description'],
        'rationale': item['rationale']
    } for item in refactoring_recs], indent=2)}
    
    Format the summary using Markdown:
    - Use '###' for main headings (e.g., ### Overview).
    - Use '*' for bullet points.
    - Provide a concise overview, then bulleted lists for key findings and recommendations.
    - Keep the entire summary under 400 words.
    """
    
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        
        return response.text
    except Exception as e:
        print(f"Error generating summary with Gemini: {e}")
        return f"Error generating AI summary: {e}\n\nPlease see the detailed report for complete information."

def create_summary_report(report_data, styles):
    """Create a single-page executive summary report"""
    elements = []
    
    elements.append(Paragraph(f"<b>{report_data['project_name']} - Executive Summary</b>", styles["CustomTitle"]))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
    elements.append(Spacer(1, 0.2*inch))
    
    print("Generating AI summary with Google Gemini...")
    summary_text = generate_summary_with_gemini(report_data)
    
    if "Error generating AI summary" in summary_text:
        elements.append(Paragraph(summary_text, styles["Normal"]))
    else:
        elements.extend(format_ai_summary(summary_text, styles))
    
    elements.append(Spacer(1, 0.2*inch))
    elements.append(Paragraph("<b>Project Metrics</b>", styles["Heading2"]))
    
    data = [
        ["Files Reviewed", str(report_data['total_files_reviewed'])],
        ["Lines of Code", str(report_data['total_lines_of_code'])],
        ["Security Findings", str(len(report_data['security_findings']))],
        ["Code Issues", str(len(report_data['issues']))],
        ["Refactoring Recommendations", str(len(report_data['refactoring_recommendations']))]
    ]
    
    table = Table(data, colWidths=[2*inch, 1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), styles['Normal'].fontName),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
    ]))
    
    elements.append(table)
    
    return elements

def generate_pdf_report(json_file, output_file, summary_file=None):
    """Generate the PDF report from the JSON data"""
    report_data = load_report_data(json_file)
    
    font_name = register_fonts()
    
    styles = create_styles(font_name)
    
    doc = SimpleDocTemplate(
        output_file,
        pagesize=letter,
        rightMargin=0.5*inch,
        leftMargin=0.5*inch,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch
    )
    
    elements = []
    
    elements.extend(create_title(doc, report_data, styles))
    elements.extend(create_executive_summary(doc, report_data, styles))
    elements.extend(create_security_section(doc, report_data, styles))
    elements.extend(create_issues_section(doc, report_data, styles))
    elements.extend(create_refactoring_section(doc, report_data, styles))
    elements.extend(create_dependency_section(doc, report_data, styles))
    elements.extend(create_control_flow_section(doc, report_data, styles))
    
    doc.build(elements)
    
    if summary_file:
        summary_doc = SimpleDocTemplate(
            summary_file,
            pagesize=letter,
            rightMargin=0.5*inch,
            leftMargin=0.5*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch
        )
        
        summary_elements = create_summary_report(report_data, styles)
        summary_doc.build(summary_elements)
        
        return output_file, summary_file
        
    return output_file

if __name__ == "__main__":
    input_file = "review-caller/review_report.json"
    output_file = "review-caller/code_review_report.pdf"
    summary_file = "review-caller/code_review_summary.pdf"
    
    try:
        detailed_report, summary_report = generate_pdf_report(input_file, output_file, summary_file)
        print(f"Detailed report generated: {os.path.abspath(detailed_report)}")
        print(f"Summary report generated: {os.path.abspath(summary_report)}")
    except Exception as e:
        print(f"Error generating reports: {e}")