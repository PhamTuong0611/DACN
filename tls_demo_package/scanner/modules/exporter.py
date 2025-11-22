"""Export scan results to multiple formats (JSON, CSV, HTML, Markdown).

Supports:
- JSON: Structured data export for API integration
- CSV: Spreadsheet-compatible format for analysis
- HTML: Professional formatted report with charts and styling
- Markdown: Documentation-ready summary with sections
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

try:
    from jinja2 import Template
except ImportError:
    Template = None


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLS Scanner Report - {{ timestamp }}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); 
            color: #333; 
            min-height: 100vh;
            padding-bottom: 40px;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 40px; 
            border-radius: 12px; 
            margin-bottom: 40px;
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }
        header h1 { margin: 0 0 10px 0; font-size: 32px; font-weight: 600; }
        header .meta { font-size: 14px; opacity: 0.95; }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
            transition: transform 0.2s, box-shadow 0.2s;
            border-top: 4px solid #667eea;
        }
        .stat-card:hover { transform: translateY(-5px); box-shadow: 0 8px 25px rgba(0, 0, 0, 0.12); }
        .stat-card.critical { border-top-color: #e74c3c; }
        .stat-card.high { border-top-color: #e67e22; }
        .stat-card.medium { border-top-color: #f39c12; }
        .stat-card.low { border-top-color: #3498db; }
        
        .stat-card h3 { color: #999; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 15px; }
        .stat-card .value { font-size: 42px; font-weight: bold; color: #333; margin-bottom: 5px; }
        .stat-card .subtext { font-size: 12px; color: #999; }
        
        .chart-container {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
            margin-bottom: 40px;
        }
        .chart-container h2 { font-size: 18px; margin-bottom: 20px; color: #333; }
        
        .results { display: grid; gap: 20px; }
        .result-card { 
            background: white; 
            border-left: 5px solid #ddd; 
            border-radius: 12px; 
            padding: 25px; 
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
            transition: box-shadow 0.2s;
        }
        .result-card:hover { box-shadow: 0 8px 25px rgba(0, 0, 0, 0.12); }
        .result-card.critical { border-left-color: #e74c3c; background: #fff5f5; }
        .result-card.high { border-left-color: #e67e22; background: #fffaf0; }
        .result-card.medium { border-left-color: #f39c12; background: #fffbf0; }
        .result-card.low { border-left-color: #3498db; background: #f0f8ff; }
        .result-card.info { border-left-color: #95a5a6; background: #f8f9fa; }
        
        .result-header { 
            display: flex; 
            justify-content: space-between; 
            align-items: start; 
            margin-bottom: 20px; 
            border-bottom: 2px solid rgba(0, 0, 0, 0.1); 
            padding-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }
        .result-url { 
            font-weight: 700; 
            font-size: 18px; 
            word-break: break-all; 
            color: #333;
            flex: 1;
            min-width: 200px;
        }
        .result-badges {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .badge { 
            display: inline-block; 
            padding: 6px 14px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge.critical { background: #e74c3c; color: white; }
        .badge.high { background: #e67e22; color: white; }
        .badge.medium { background: #f39c12; color: white; }
        .badge.low { background: #3498db; color: white; }
        .badge.info { background: #95a5a6; color: white; }
        .badge.status { background: #667eea; color: white; }
        
        .score-bar {
            width: 100%;
            height: 8px;
            background: #f0f0f0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        .score-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        .section { margin-top: 20px; }
        .section-title { 
            font-weight: 700; 
            margin-bottom: 15px; 
            color: #333; 
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding-bottom: 10px;
            border-bottom: 2px solid rgba(0, 0, 0, 0.1);
        }
        
        .finding { 
            background: #f9f9f9; 
            border-left: 4px solid #ddd; 
            padding: 12px 15px; 
            margin-bottom: 10px; 
            border-radius: 6px;
            transition: all 0.2s;
        }
        .finding:hover { background: #f5f5f5; }
        .finding.critical { border-left-color: #e74c3c; background: #ffebee; }
        .finding.high { border-left-color: #e67e22; background: #fff3e0; }
        .finding.medium { border-left-color: #f39c12; background: #fffbea; }
        .finding.low { border-left-color: #3498db; background: #e3f2fd; }
        
        .finding-severity { 
            font-weight: 700; 
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .finding-rule { 
            color: #666; 
            font-family: 'Courier New', monospace;
            font-size: 12px;
            background: rgba(0, 0, 0, 0.05);
            padding: 2px 6px;
            border-radius: 3px;
            margin: 0 5px;
        }
        
        .suggestion { 
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); 
            border-left: 4px solid #28a745; 
            padding: 12px 15px; 
            margin-bottom: 10px; 
            border-radius: 6px;
        }
        .suggestion:before { content: "✓ "; font-weight: bold; }
        
        .tls-info { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
            gap: 15px; 
            margin-top: 15px;
        }
        .tls-item { 
            background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%); 
            padding: 15px; 
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .tls-label { 
            font-weight: 700; 
            color: #667eea; 
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .tls-value { 
            font-family: 'Courier New', monospace; 
            font-size: 13px; 
            word-break: break-all; 
            margin-top: 8px;
            color: #333;
        }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 15px 0;
            font-size: 13px;
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #e0e0e0;
            font-family: 'Courier New', monospace;
        }
        th { 
            background: linear-gradient(135deg, #f5f5f5 0%, #e0e0e0 100%); 
            font-weight: 700;
            color: #333;
        }
        tr:hover { background: #fafafa; }
        
        .error { 
            background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%); 
            border-left: 4px solid #e74c3c; 
            padding: 15px; 
            border-radius: 8px; 
            color: #c62828;
            font-weight: 500;
        }
        
        .no-findings {
            background: #e8f5e9;
            border: 2px solid #4caf50;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: #2e7d32;
            font-weight: 500;
        }
        
        footer { 
            margin-top: 60px; 
            padding-top: 30px; 
            border-top: 2px solid rgba(0, 0, 0, 0.1); 
            text-align: center; 
            font-size: 12px; 
            color: #999;
        }
        
        @media print {
            body { background: white; }
            .container { padding: 0; }
            .result-card { box-shadow: none; border: 1px solid #ddd; }
            .stat-card { box-shadow: none; border: 1px solid #ddd; }
        }
        
        @media (max-width: 768px) {
            header { padding: 20px; }
            header h1 { font-size: 24px; }
            .dashboard { grid-template-columns: 1fr; }
            .result-header { flex-direction: column; }
            .stat-card .value { font-size: 32px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 TLS Security Scanner Report</h1>
            <div class="meta">
                <p><strong>Generated:</strong> {{ timestamp }}</p>
                <p><strong>Targets Scanned:</strong> {{ total_targets }} | <strong>Critical:</strong> {{ critical_count }} | <strong>High:</strong> {{ high_count }} | <strong>Medium:</strong> {{ medium_count }}</p>
            </div>
        </header>
        
        <div class="dashboard">
            <div class="stat-card">
                <h3>Total Targets</h3>
                <div class="value">{{ total_targets }}</div>
            </div>
            <div class="stat-card critical">
                <h3>🔴 Critical Issues</h3>
                <div class="value" style="color: #e74c3c;">{{ critical_count }}</div>
                <div class="subtext">Requires immediate action</div>
            </div>
            <div class="stat-card high">
                <h3>🟠 High Issues</h3>
                <div class="value" style="color: #e67e22;">{{ high_count }}</div>
                <div class="subtext">Significant vulnerabilities</div>
            </div>
            <div class="stat-card medium">
                <h3>🟡 Medium Issues</h3>
                <div class="value" style="color: #f39c12;">{{ medium_count }}</div>
                <div class="subtext">Recommended fixes</div>
            </div>
        </div>
        
        {% if critical_count > 0 or high_count > 0 or medium_count > 0 %}
        <div class="chart-container">
            <h2>Security Issues Summary</h2>
            <canvas id="riskChart" style="max-height: 300px;"></canvas>
        </div>
        {% endif %}
        
        <div class="results">
        {% for result in results %}
            <div class="result-card {{ result.risk|lower }}">
                <div class="result-header">
                    <div class="result-url">🌐 {{ result.url }}</div>
                    <div class="result-badges">
                        {% if result.error %}
                            <span class="badge critical">⚠️ ERROR</span>
                        {% else %}
                            <span class="badge {{ result.risk|lower }}">{{ result.risk }}</span>
                            <span class="badge status">HTTP {{ result.status }}</span>
                        {% endif %}
                    </div>
                </div>
                
                {% if result.error %}
                    <div class="error">⚠️ Error: {{ result.error }}</div>
                {% else %}
                    {% if result.score >= 0 %}
                    <div style="margin-bottom: 15px;">
                        <strong>Risk Score:</strong> {{ result.score }}/100
                        <div class="score-bar">
                            <div class="score-bar-fill" style="width: {{ result.score|min(100) }}%"></div>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if result.findings %}
                    <div class="section">
                        <div class="section-title">⚠️ Findings ({{ result.findings|length }})</div>
                        {% for finding in result.findings %}
                            <div class="finding {{ finding.severity|lower }}">
                                <span class="finding-severity">● {{ finding.severity }}</span> 
                                <span class="finding-rule">{{ finding.rule }}</span><br>
                                <span style="color: #666; margin-top: 5px; display: block;">{{ finding.detail }}</span>
                            </div>
                        {% endfor %}
                    </div>
                    {% else %}
                    <div class="no-findings">✓ No security findings detected</div>
                    {% endif %}
                    
                    {% if result.suggestions %}
                    <div class="section">
                        <div class="section-title">💡 Recommendations</div>
                        {% for suggestion in result.suggestions %}
                            <div class="suggestion">{{ suggestion }}</div>
                        {% endfor %}
                    </div>
                    {% endif %}
                    
                    {% if result.tls and not result.tls.error %}
                    <div class="section">
                        <div class="section-title">🔐 TLS Information</div>
                        <div class="tls-info">
                            <div class="tls-item">
                                <div class="tls-label">TLS Version</div>
                                <div class="tls-value">{{ result.tls.protocol }}</div>
                            </div>
                            <div class="tls-item">
                                <div class="tls-label">Cipher Suite</div>
                                <div class="tls-value">{{ result.tls.cipher.name }}</div>
                            </div>
                            <div class="tls-item">
                                <div class="tls-label">Cipher Strength</div>
                                <div class="tls-value">{{ result.tls.cipher.bits }} bits</div>
                            </div>
                            {% if result.tls.certificate %}
                            <div class="tls-item">
                                <div class="tls-label">Certificate Expires</div>
                                <div class="tls-value">{{ result.tls.certificate.not_after }}</div>
                            </div>
                            <div class="tls-item">
                                <div class="tls-label">Subject</div>
                                <div class="tls-value">{{ result.tls.certificate.subject }}</div>
                            </div>
                            {% if result.tls.certificate.issuer %}
                            <div class="tls-item">
                                <div class="tls-label">Issuer</div>
                                <div class="tls-value">{{ result.tls.certificate.issuer }}</div>
                            </div>
                            {% endif %}
                            {% endif %}
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if result.headers %}
                    <div class="section">
                        <div class="section-title">📋 HTTP Headers ({{ result.headers|length }})</div>
                        <table>
                            <tbody>
                            {% for key, value in result.headers.items() %}
                                <tr>
                                    <th style="width: 25%;">{{ key }}</th>
                                    <td>{{ value }}</td>
                                </tr>
                            {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% endif %}
                {% endif %}
            </div>
        {% endfor %}
        </div>
        
        <footer>
            <p>Report generated by <strong>TLS Security Scanner</strong></p>
            <p>For more information and source code, visit: <a href="https://github.com/yourusername/tls-scanner" target="_blank">GitHub Repository</a></p>
            <p style="margin-top: 10px; color: #ccc;">{{ timestamp }}</p>
        </footer>
    </div>
    
    <script>
    {% if critical_count > 0 or high_count > 0 or medium_count > 0 %}
    const ctx = document.getElementById('riskChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [{{ critical_count }}, {{ high_count }}, {{ medium_count }}, {{ low_count }}],
                backgroundColor: ['#e74c3c', '#e67e22', '#f39c12', '#3498db'],
                borderColor: '#fff',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { padding: 20, font: { size: 12, weight: 'bold' } }
                }
            }
        }
    });
    {% endif %}
    </script>
</body>
</html>
"""

MARKDOWN_TEMPLATE = """# TLS Security Scan Report

**Report Generated**: {{ timestamp }}

---

## Executive Summary

| Metric | Count |
|--------|-------|
| **Total Targets** | {{ total_targets }} |
| **🔴 Critical Issues** | {{ critical_count }} |
| **🟠 High Issues** | {{ high_count }} |
| **🟡 Medium Issues** | {{ medium_count }} |
| **🔵 Low Issues** | {{ low_count }} |

---

## Risk Overview

{% if critical_count > 0 %}
### ⚠️ CRITICAL FINDINGS
Your environment has **{{ critical_count }}** critical security issues that require immediate remediation.

{% endif %}

{% if high_count > 0 %}
### ⚠️ HIGH PRIORITY ISSUES  
There are **{{ high_count }}** high-severity findings that should be addressed promptly.

{% endif %}

{% if medium_count == 0 and high_count == 0 and critical_count == 0 %}
### ✅ No Critical Issues Found
Your scanned targets are in good security posture.

{% endif %}

---

## Detailed Findings

{% for result in results %}
### 🌐 {{ result.url }}

{% if result.error %}
**Status**: ❌ ERROR  
**Error Message**: {{ result.error }}

---
{% else %}

**Overall Risk Level**: {{ result.risk }}  
**HTTP Status**: {{ result.status }}  
**Risk Score**: {{ result.score }}/100

{% if not result.findings %}
✅ **No security findings detected for this target.**

{% else %}

#### Identified Issues

{% for finding in result.findings %}
**[{{ finding.severity }}]** `{{ finding.rule }}`
- {{ finding.detail }}

{% endfor %}

#### Recommendations

{% for suggestion in result.suggestions %}
✓ {{ suggestion }}

{% endfor %}

{% endif %}

#### TLS/SSL Information

{% if result.tls.error %}
- **Status**: ❌ {{ result.tls.error }}

{% else %}
| Property | Value |
|----------|-------|
| **TLS Version** | {{ result.tls.protocol }} |
| **Cipher Suite** | {{ result.tls.cipher.name }} |
| **Cipher Strength** | {{ result.tls.cipher.bits }} bits |
{% if result.tls.certificate %}
| **Subject** | {{ result.tls.certificate.subject }} |
| **Issuer** | {{ result.tls.certificate.issuer }} |
| **Expires** | {{ result.tls.certificate.not_after }} |
{% if result.tls.certificate.subject_alt_names %}
| **SANs** | {{ result.tls.certificate.subject_alt_names }} |
{% endif %}
{% endif %}

{% endif %}

#### HTTP Security Headers

| Header | Value |
|--------|-------|
{% for key, value in result.headers.items() %}
| **{{ key }}** | {{ value }} |
{% endfor %}

---

{% endif %}
{% endfor %}

## Summary & Next Steps

### Critical Actions Required
{% if critical_count > 0 %}
- Address all **{{ critical_count }}** critical findings immediately
- Test changes in staging environment before production deployment
- Consider engaging security team for peer review
{% else %}
- No critical actions required at this time
{% endif %}

### Recommended Next Steps
1. Review all findings against your security policy
2. Prioritize fixes based on CVSS score and business impact
3. Implement recommended security headers
4. Schedule regular security audits (quarterly or after major changes)
5. Monitor certificate expiration dates

---

**Report Generated By**: TLS Security Scanner  
**Generated At**: {{ timestamp }}  
**For Questions**: Contact your security team
"""


class ReportExporter:
    """Export scan results to various formats."""
    
    @staticmethod
    def to_json(results: List[Dict], filepath: Optional[str] = None) -> str:
        """Export results to JSON format."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "total_targets": len(results),
            "results": results,
        }
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        
        if filepath:
            Path(filepath).write_text(json_str, encoding="utf-8")
        
        return json_str
    
    @staticmethod
    def to_csv(results: List[Dict], filepath: str) -> str:
        """Export results to CSV format."""
        rows = []
        
        for result in results:
            row = {
                "URL": result.get("url", ""),
                "Status": result.get("status", ""),
                "Risk": result.get("risk", ""),
                "Score": result.get("score", ""),
                "HTTP_Status": result.get("status", ""),
                "TLS_Version": result.get("tls", {}).get("protocol", "") if isinstance(result.get("tls"), dict) else "",
                "Cipher": result.get("tls", {}).get("cipher", {}).get("name", "") if isinstance(result.get("tls"), dict) else "",
                "Cipher_Bits": result.get("tls", {}).get("cipher", {}).get("bits", "") if isinstance(result.get("tls"), dict) else "",
                "Findings_Count": len(result.get("findings", [])),
                "Critical_Issues": sum(1 for f in result.get("findings", []) if f.get("severity") == "CRITICAL"),
                "High_Issues": sum(1 for f in result.get("findings", []) if f.get("severity") == "HIGH"),
                "Medium_Issues": sum(1 for f in result.get("findings", []) if f.get("severity") == "MEDIUM"),
                "Findings_Summary": "; ".join([f"{f.get('rule')}" for f in result.get("findings", [])][:5]),
            }
            rows.append(row)
        
        if rows:
            fieldnames = rows[0].keys()
            with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        
        return filepath
    
    @staticmethod
    def to_html(results: List[Dict], filepath: Optional[str] = None) -> str:
        """Export results to HTML format with charts and professional styling."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        critical_count = sum(1 for r in results if r.get("risk") == "CRITICAL")
        high_count = sum(1 for r in results if r.get("risk") == "HIGH")
        medium_count = sum(1 for r in results if r.get("risk") == "MEDIUM")
        low_count = sum(1 for r in results if r.get("risk") == "LOW")
        
        if Template:
            template = Template(HTML_TEMPLATE)
            html_str = template.render(
                timestamp=timestamp,
                total_targets=len(results),
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                results=results,
            )
        else:
            # Fallback if Jinja2 not available
            html_str = f"""
            <html>
            <head><title>TLS Scan Report</title></head>
            <body>
            <h1>TLS Scan Report - {timestamp}</h1>
            <p>Total Targets: {len(results)}</p>
            <p>Critical: {critical_count} | High: {high_count} | Medium: {medium_count} | Low: {low_count}</p>
            <p><em>For full formatting, install Jinja2: pip install jinja2</em></p>
            </body>
            </html>
            """
        
        if filepath:
            Path(filepath).write_text(html_str, encoding="utf-8")
        
        return html_str
    
    @staticmethod
    def to_markdown(results: List[Dict], filepath: Optional[str] = None) -> str:
        """Export results to Markdown format with comprehensive documentation."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        critical_count = sum(1 for r in results if r.get("risk") == "CRITICAL")
        high_count = sum(1 for r in results if r.get("risk") == "HIGH")
        medium_count = sum(1 for r in results if r.get("risk") == "MEDIUM")
        low_count = sum(1 for r in results if r.get("risk") == "LOW")
        
        if Template:
            template = Template(MARKDOWN_TEMPLATE)
            md_str = template.render(
                timestamp=timestamp,
                total_targets=len(results),
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                results=results,
            )
        else:
            md_str = f"""# TLS Security Scan Report

Generated: {timestamp}

## Summary
- Total Targets: {len(results)}
- Critical Issues: {critical_count}
- High Issues: {high_count}
- Medium Issues: {medium_count}
- Low Issues: {low_count}

(For full formatting with Jinja2 templates, install: pip install jinja2)
"""
        
        if filepath:
            Path(filepath).write_text(md_str, encoding="utf-8")
        
        return md_str


def export_results(
    results: List[Dict],
    output_dir: str = "./reports",
    formats: List[str] = None,
) -> Dict[str, str]:
    """Export results to multiple formats at once.
    
    Args:
        results: List of scan result dictionaries
        output_dir: Directory to save exported files
        formats: List of formats to export (json, csv, html, markdown)
                If None, defaults to all formats
    
    Returns:
        Dictionary mapping format names to file paths
        
    Example:
        >>> results = [{"url": "example.com", "risk": "LOW", ...}]
        >>> exported = export_results(results, "./reports", ["json", "html"])
        >>> print(exported)
        {'json': './reports/report_20231122_120000.json',
         'html': './reports/report_20231122_120000.html'}
    """
    if formats is None:
        formats = ["json", "csv", "html", "markdown"]
    
    # Normalize format names to lowercase
    formats = [fmt.lower() for fmt in formats]
    
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exported_files = {}
    
    exporter = ReportExporter()
    
    if "json" in formats:
        json_file = output_dir_path / f"report_{timestamp}.json"
        exporter.to_json(results, str(json_file))
        exported_files["json"] = str(json_file)
    
    if "csv" in formats:
        csv_file = output_dir_path / f"report_{timestamp}.csv"
        exporter.to_csv(results, str(csv_file))
        exported_files["csv"] = str(csv_file)
    
    if "html" in formats:
        html_file = output_dir_path / f"report_{timestamp}.html"
        exporter.to_html(results, str(html_file))
        exported_files["html"] = str(html_file)
    
    if "markdown" in formats:
        md_file = output_dir_path / f"report_{timestamp}.md"
        exporter.to_markdown(results, str(md_file))
        exported_files["markdown"] = str(md_file)
    
    return exported_files
