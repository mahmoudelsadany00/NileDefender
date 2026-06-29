from openai import OpenAI
import json
import configparser
import argparse
import os
import html
import base64
from datetime import datetime
from sqlalchemy import create_engine, text
from weasyprint import HTML

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_client = None

def _get_client():
    global _client
    if _client is None:
        config = configparser.ConfigParser()
        config.read(os.path.join(SCRIPT_DIR, 'config.ini'))
        api_key = config.get('API_KEYS', 'openai')
        _client = OpenAI(api_key=api_key)
    return _client

def get_scan_vulnerabilities(db_path, scan_id):
    engine = create_engine(f'sqlite:///{db_path}')
    with engine.connect() as conn:
        vulns = conn.execute(text("""
            SELECT vulnerability_type, severity, url, method, parameter, payload, evidence
            FROM vulnerabilities WHERE scan_id = :scan_id
        """), {'scan_id': scan_id}).fetchall()
        domain_row = conn.execute(text("SELECT domain FROM scan_history WHERE id = :scan_id"), {'scan_id': scan_id}).fetchone()
        domain = domain_row[0] if domain_row else "Unknown"
    return {
        'domain': domain,
        'total_vulnerabilities': len(vulns),
        'vulnerabilities': [{'type': v[0], 'severity': v[1], 'url': v[2], 'method': v[3], 'parameter': v[4], 'payload': v[5], 'evidence': v[6]} for v in vulns]
    }

def get_fake_cvss(severity):
    if severity == 'Critical': return '9.8'
    if severity == 'High': return '8.8'
    if severity == 'Medium': return '6.5'
    if severity == 'Low': return '3.0'
    return '0.0'

def generate_report_html(vuln_data):
    sev_colors = {'Critical': '#dc2626', 'High': '#ea580c', 'Medium': '#ca8a04', 'Low': '#16a34a', 'Info': '#6b7280'}
    sev_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    unique_types = set()
    
    for v in vuln_data['vulnerabilities']:
        sev_counts[v['severity']] = sev_counts.get(v['severity'], 0) + 1
        unique_types.add(v['type'])
        
    overall_risk = "Info"
    for s in ['Critical', 'High', 'Medium', 'Low']:
        if sev_counts.get(s, 0) > 0:
            overall_risk = s
            break

    client = _get_client()
    
    ai_prompt = f"""You are an elite penetration tester.
    Target: {vuln_data['domain']}
    Total findings: {vuln_data['total_vulnerabilities']}
    Severities: {json.dumps(sev_counts)}
    Unique vulnerability types found: {list(unique_types)}
    
    Task: Return a strict JSON response (NO MARKDOWN WRAPPERS) with the following structure:
    {{
        "executive_summary": "3 paragraphs of professional executive summary.",
        "vulnerability_knowledge": {{
            "VULN_TYPE": {{
                "description": "2 sentences explaining the vulnerability.",
                "impact": "2 sentences explaining the business impact.",
                "remediation": "2 sentences explaining how to fix it."
            }}
        }},
        "conclusion": "2 paragraphs of professional conclusion summarizing the assessment and providing general security recommendations. Use \\n\\n for paragraphs."
    }}
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            response_format={ "type": "json_object" },
            messages=[{"role": "user", "content": ai_prompt}]
        )
        ai_intel = json.loads(response.choices[0].message.content)
    except Exception as e:
        ai_intel = {
            "executive_summary": "The security assessment identified multiple vulnerabilities that require immediate attention.",
            "vulnerability_knowledge": {}
        }
    
    logo_path = os.path.join(SCRIPT_DIR, 'frontend', 'public', 'logo.png')
    logo_b64 = ""
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            logo_b64 = base64.b64encode(f.read()).decode('utf-8')

    html_out = f"""<!DOCTYPE html>
    <html>
    <head>
    <style>
        @page {{ margin: 15mm 15mm; size: A4; @bottom-center {{ content: counter(page); font-size: 10px; color: #888; }} }}
        @page:first {{ background-color: #0a1628; margin: 0; @bottom-center {{ content: ""; }} }}
        body {{ font-family: 'Segoe UI', -apple-system, Arial, sans-serif; color: #1e293b; line-height: 1.5; font-size: 13px; }}
        
        .cover-page {{ text-align: center; page-break-after: always; padding-top: 150px; color: white; height: 100%; }}
        .cover-page img {{ width: 180px; margin-bottom: 20px; }}
        .cover-title {{ font-size: 38px; color: #7ec8e3; letter-spacing: 3px; margin: 0; font-weight: bold; }}
        .cover-subtitle {{ font-size: 16px; color: #8899aa; margin-top: 5px; margin-bottom: 80px; }}
        .cover-report-type {{ font-size: 26px; color: white; font-weight: bold; margin-bottom: 50px; }}
        .cover-box {{ background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 30px; display: inline-block; text-align: left; margin-top: 20px; }}
        .cover-box p {{ margin: 8px 0; font-size: 15px; color: #cbd5e1; }}
        .cover-box strong {{ color: white; width: 150px; display: inline-block; }}
        
        h1 {{ color: #141E46; font-size: 16px; border-left: 3px solid #7ec8e3; padding-left: 10px; margin-top: 35px; margin-bottom: 20px; text-transform: uppercase; page-break-after: avoid; }}
        p {{ margin-bottom: 12px; color: #334155; orphans: 3; widows: 3; font-size: 11px; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 25px; page-break-inside: auto; }}
        tr {{ page-break-inside: avoid; page-break-after: auto; }}
        th, td {{ padding: 12px 10px; text-align: left; border: 1px solid #e2e8f0; font-size: 11px; }}
        th {{ background-color: #141E46; color: white; font-weight: bold; font-size: 11px; }}
        tr:nth-child(even) {{ background-color: #f8fafc; }}
        
        .badge {{ padding: 3px 8px; border-radius: 12px; color: white; font-weight: bold; font-size: 10px; display: inline-block; text-transform: uppercase; }}
        
        /* CARDS */
        .card {{ border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 20px; box-shadow: 0 1px 2px rgba(0,0,0,0.02); page-break-inside: avoid; }}
        .card-header {{ background: #f8fafc; padding: 10px 15px; font-weight: bold; font-size: 14px; border-bottom: 1px solid #e2e8f0; color: #0f172a; display: flex; justify-content: space-between; align-items: center; page-break-after: avoid; }}
        .card-body {{ padding: 15px; }}
        .card-body p {{ margin: 0 0 8px 0; font-size: 11px; }}
        
        .code {{ background: #f1f5f9; padding: 10px; font-family: monospace; font-size: 10px; border: 1px solid #e2e8f0; border-radius: 4px; word-break: break-all; margin-top: 5px; color: #0f172a; max-height: 120px; overflow: hidden; }}
        
        .impact-box {{ border-left: 3px solid #ef4444; background: #fef2f2; padding: 10px; margin-top: 12px; border-radius: 0 4px 4px 0; font-size: 11px; color: #333; }}
        .rem-box {{ border-left: 3px solid #22c55e; background: #f0fdf4; padding: 10px; margin-top: 8px; border-radius: 0 4px 4px 0; font-size: 11px; color: #333; }}
    </style>
    </head>
    <body>
    
    <div class="cover-page">
        <img src="data:image/png;base64,{logo_b64}" alt="Logo">
        <h1 class="cover-title" style="border:none; margin:0; padding:0;">NileDefender</h1>
        <div class="cover-subtitle">Web Vulnerability Scanner</div>
        
        <div class="cover-report-type">SECURITY ASSESSMENT REPORT</div>
        <div style="color: #8899aa; font-size: 14px; margin-bottom: 20px;">Penetration Testing Report</div>
        
        <div class="cover-box">
            <p><strong>Target Domain:</strong> {vuln_data['domain']}</p>
            <p><strong>Assessment Date:</strong> {datetime.now().strftime("%B %d, %Y")}</p>
            <p><strong>Total Findings:</strong> {vuln_data['total_vulnerabilities']}</p>
            <p><strong>Overall Risk:</strong> <span style="color: {sev_colors.get(overall_risk, '#fff')}; font-weight: bold;">{overall_risk}</span></p>
        </div>
    </div>
    
    <div class="content-container">
        <h1>EXECUTIVE SUMMARY</h1>
        <p>{ai_intel.get('executive_summary', '').replace('\n', '<br>')}</p>
        
        <h1>RISK OVERVIEW</h1>
        <div style="width: 80%; margin-bottom: 30px;">"""
            
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        count = sev_counts.get(sev, 0)
        width = max(1, (count / max(1, vuln_data['total_vulnerabilities'])) * 100) if count > 0 else 0
        
        # Exact match of the screenshot's bar design
        html_out += f"""
            <div style="margin-top: 15px;">
                <div style="height: 12px; width: 100%; background-color: #f1f5f9; margin-bottom: 5px;">
                    <div style="height: 100%; width: {width}%; background-color: {sev_colors[sev]};"></div>
                </div>
                <div style="font-size: 11px; color: #333;">
                    <span style="float: left;">{sev}:</span>
                    <span style="float: right;">{count}</span>
                    <div style="clear: both;"></div>
                </div>
            </div>"""
            
    html_out += f"""
            <h2 style="color: {sev_colors.get(overall_risk, '#000')}; margin-top: 25px; font-size: 18px; font-weight: bold;">{overall_risk}</h2>
        </div>
        
        <h1 style="page-break-before: always;">VULNERABILITY SUMMARY TABLE</h1>
        <table>
            <tr>
                <th style="width: 5%">#</th>
                <th style="width: 20%">Vulnerability Type</th>
                <th style="width: 15%">Severity</th>
                <th style="width: 35%">Affected URL</th>
                <th style="width: 15%">Parameter</th>
                <th style="width: 10%">CVSS Score</th>
            </tr>"""
            
    for i, v in enumerate(vuln_data['vulnerabilities'], 1):
        # The Severity cell background is completely colored, text is white
        html_out += f"""<tr>
            <td style="text-align: center;">{i}</td>
            <td style="font-weight: bold; color: #1e293b;">{v['type']}</td>
            <td style="background-color: {sev_colors.get(v['severity'], '#000')}; color: white; text-align: center; font-weight: bold;">{v['severity']}</td>
            <td style="font-family: monospace; color: #0369a1; word-break: break-all;">{v['url']}</td>
            <td><code>{v['parameter']}</code></td>
            <td style="text-align: center;">{get_fake_cvss(v['severity'])}</td>
        </tr>"""
            
    html_out += "</table><h1 style=\"page-break-before: always;\">DETAILED FINDINGS</h1>"
    
    for i, v in enumerate(vuln_data['vulnerabilities'], 1):
        vuln_knowledge = ai_intel.get('vulnerability_knowledge', {}).get(v['type'], {})
        desc = vuln_knowledge.get('description', f"The application fails to securely process user input, leading to {v['type']}.")
        impact = vuln_knowledge.get('impact', "This vulnerability can be exploited by an attacker to compromise the application.")
        rem = vuln_knowledge.get('remediation', "Implement strict input validation and output encoding.")
        
        escaped_payload = html.escape(str(v['payload'] or v['evidence'] or 'No specific payload recorded.'))
        
        html_out += f"""
        <div class="card">
            <div class="card-header">
                <div><span style="color: #64748b; margin-right: 5px;">#{i}</span> {v['type']}</div>
                <span class="badge" style="background: {sev_colors.get(v['severity'], '#000')}">{v['severity']}</span>
            </div>
            <div class="card-body">
                <p><strong>Affected URL:</strong> <span style="font-family: monospace; color: #0369a1;">{v['url']}</span></p>
                <p><strong>Vulnerable Parameter:</strong> <code style="background: #f1f5f9; padding: 2px 4px; border-radius: 4px;">{v['parameter']}</code></p>
                <p><strong>Description:</strong> {desc}</p>
                
                <p style="margin-top: 10px; font-weight: bold;">Evidence / Payload:</p>
                <div class="code">{escaped_payload}</div>
            </div>
        </div>"""
        
    html_out += f"""
        <h1 style="page-break-before: always;">IMPACT & REMEDIATION STRATEGIES</h1>
        <p>The following section details the business impact and recommended remediation steps for each vulnerability class identified during the assessment.</p>
    """
    
    for u_type in sorted(unique_types):
        vuln_knowledge = ai_intel.get('vulnerability_knowledge', {}).get(u_type, {})
        impact = vuln_knowledge.get('impact', f"The application is vulnerable to {u_type}, which may allow attackers to compromise the integrity or confidentiality of the application.")
        rem = vuln_knowledge.get('remediation', "Implement strict input validation, output encoding, and follow secure coding practices specific to this vulnerability.")
            
        html_out += f"""
        <div style="font-size: 16px; font-weight: bold; color: #0f172a; margin-top: 30px; border-bottom: 2px solid #e2e8f0; padding-bottom: 5px; margin-bottom: 10px;">{u_type}</div>
        <div class="impact-box">
            <strong style="color: #b91c1c;">Business Impact:</strong><br>
            {impact}
        </div>
        <div class="rem-box">
            <strong style="color: #15803d;">Remediation Strategy:</strong><br>
            {rem}
        </div>
        """
        
    html_out += f"""
        <h1 style="page-break-before: always;">CONCLUSION & RECOMMENDATIONS</h1>
        <p>{ai_intel.get('conclusion', 'The assessment highlights the importance of regular security testing and vulnerability management. It is recommended that the organization prioritizes the remediation of the identified vulnerabilities and implements additional security measures to prevent similar vulnerabilities in the future.').replace('\\n', '<br>')}</p>
    </div>
    </body></html>"""
    
    return html_out

def html_to_pdf_bytes(html_content):
    return HTML(string=html_content).write_pdf()

def generate_report(db_path, scan_id, output_pdf):
    vuln_data = get_scan_vulnerabilities(db_path, scan_id)
    html_content = generate_report_html(vuln_data)
    HTML(string=html_content).write_pdf(output_pdf)
    return output_pdf

if __name__ == "__main__":
    generate_report("output/niledefender.db", 1, "test_report.pdf")
