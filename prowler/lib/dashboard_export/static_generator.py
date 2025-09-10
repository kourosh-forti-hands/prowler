#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Static HTML Generator

This module generates self-contained HTML files with embedded Plotly charts
and data for offline dashboard viewing.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

import plotly.graph_objects as go
import plotly.express as px
from plotly.offline import plot

from prowler.lib.logger import logger


class StaticHTMLGenerator:
    """Generates static HTML files with embedded data and charts"""
    
    def __init__(self):
        """Initialize the static HTML generator"""
        self.template_dir = Path(__file__).parent / "templates"
        
        # Define colors matching the original dashboard
        self.colors = {
            'fail': '#e67272',
            'pass': '#54d283', 
            'info': '#2684FF',
            'manual': '#636c78',
            'muted_fail': '#fca903',
            'muted_pass': '#03fccf',
            'critical': '#951649',
            'high': '#e11d48',
            'medium': '#ee6f15',
            'low': '#fcf45d',
            'informational': '#3274d9'
        }
    
    def generate_static_html(self, dashboard_data: Dict[str, Any]) -> str:
        """
        Generate a complete single-file static HTML dashboard
        
        Args:
            dashboard_data: Processed dashboard data
            
        Returns:
            Complete HTML string with embedded data and charts
        """
        try:
            logger.info("Generating static HTML dashboard")
            
            # Generate charts
            charts_html = self._generate_all_charts(dashboard_data)
            
            # Generate summary cards
            cards_html = self._generate_summary_cards(dashboard_data)
            
            # Embed data as JSON
            data_json = json.dumps(dashboard_data, indent=2, default=str)
            
            # Read base template
            template_content = self._read_template("static_dashboard.html")
            
            # Replace placeholders
            html_content = template_content.replace("{{DASHBOARD_TITLE}}", "Prowler Security Dashboard")
            html_content = html_content.replace("{{EXPORT_TIMESTAMP}}", dashboard_data.get('export_timestamp', ''))
            html_content = html_content.replace("{{SUMMARY_CARDS}}", cards_html)
            html_content = html_content.replace("{{CHARTS_CONTENT}}", charts_html)
            html_content = html_content.replace("{{DASHBOARD_DATA}}", data_json)
            html_content = html_content.replace("{{TOTAL_FINDINGS}}", str(dashboard_data.get('total_findings', 0)))
            
            return html_content
            
        except Exception as e:
            logger.error(f"Failed to generate static HTML: {str(e)}")
            return self._generate_error_html(str(e))
    
    def generate_overview_page(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate overview page for portable export"""
        try:
            charts_html = self._generate_overview_charts(dashboard_data)
            cards_html = self._generate_summary_cards(dashboard_data)
            
            template_content = self._read_template("overview_template.html")
            html_content = template_content.replace("{{SUMMARY_CARDS}}", cards_html)
            html_content = html_content.replace("{{OVERVIEW_CHARTS}}", charts_html)
            html_content = html_content.replace("{{TOTAL_FINDINGS}}", str(dashboard_data.get('total_findings', 0)))
            
            return html_content
        except Exception as e:
            logger.error(f"Failed to generate overview page: {str(e)}")
            return self._generate_error_html(str(e))
    
    def generate_compliance_page(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate compliance page for portable export"""
        try:
            compliance_html = self._generate_compliance_charts(dashboard_data)
            
            template_content = self._read_template("compliance_template.html")
            html_content = template_content.replace("{{COMPLIANCE_CHARTS}}", compliance_html)
            
            return html_content
        except Exception as e:
            logger.error(f"Failed to generate compliance page: {str(e)}")
            return self._generate_error_html(str(e))
    
    def generate_index_page(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate index page with navigation for portable export"""
        try:
            summary_stats = dashboard_data.get('summary_stats', {})
            
            index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prowler Security Dashboard</title>
    <style>
        {self._get_base_css()}
    </style>
</head>
<body>
    <div class="container">
        <header class="dashboard-header">
            <h1>🛡️ Prowler Security Dashboard</h1>
            <p class="subtitle">Cloud Security Assessment Results</p>
            <div class="export-info">
                <small>Generated: {dashboard_data.get('export_timestamp', '')}</small>
            </div>
        </header>
        
        <div class="quick-stats">
            <div class="stat-card">
                <h3>{dashboard_data.get('total_findings', 0)}</h3>
                <p>Total Findings</p>
            </div>
            <div class="stat-card">
                <h3>{summary_stats.get('scan_summary', {}).get('providers_scanned', 0)}</h3>
                <p>Providers Scanned</p>
            </div>
            <div class="stat-card">
                <h3>{summary_stats.get('scan_summary', {}).get('accounts_scanned', 0)}</h3>
                <p>Accounts Scanned</p>
            </div>
            <div class="stat-card">
                <h3>{summary_stats.get('scan_summary', {}).get('pass_rate', 0)}%</h3>
                <p>Pass Rate</p>
            </div>
        </div>
        
        <div class="navigation-cards">
            <div class="nav-card" onclick="window.location.href='overview.html'">
                <h2>📊 Overview</h2>
                <p>Comprehensive view of all findings, statistics, and trends across your cloud infrastructure.</p>
                <div class="nav-stats">
                    <span class="stat-pill fail">{summary_stats.get('by_status', {}).get('FAIL', 0)} Failed</span>
                    <span class="stat-pill pass">{summary_stats.get('by_status', {}).get('PASS', 0)} Passed</span>
                </div>
            </div>
            
            <div class="nav-card" onclick="window.location.href='compliance.html'">
                <h2>📋 Compliance</h2>
                <p>Detailed compliance framework results and requirements mapping.</p>
                <div class="nav-stats">
                    <span class="stat-pill info">{len(dashboard_data.get('compliance_data', {}))} Frameworks</span>
                </div>
            </div>
        </div>
        
        <footer class="dashboard-footer">
            <p>Powered by <strong>Prowler</strong> - Cloud Security Assessment Tool</p>
            <p><small>This dashboard is self-contained and works completely offline.</small></p>
        </footer>
    </div>
</body>
</html>"""
            return index_html
        except Exception as e:
            logger.error(f"Failed to generate index page: {str(e)}")
            return self._generate_error_html(str(e))
    
    def _generate_all_charts(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate all charts for the complete dashboard"""
        charts_html = ""
        
        try:
            # Status pie chart
            charts_html += self._generate_status_chart(dashboard_data)
            
            # Severity distribution
            charts_html += self._generate_severity_chart(dashboard_data)
            
            # Provider breakdown
            charts_html += self._generate_provider_chart(dashboard_data)
            
            # Top failing services
            charts_html += self._generate_services_chart(dashboard_data)
            
            # Findings by region
            charts_html += self._generate_region_chart(dashboard_data)
            
        except Exception as e:
            logger.error(f"Failed to generate charts: {str(e)}")
            charts_html += f"<div class='error-message'>Error generating charts: {str(e)}</div>"
        
        return charts_html
    
    def _generate_overview_charts(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate charts specifically for overview page"""
        return self._generate_all_charts(dashboard_data)
    
    def _generate_compliance_charts(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate compliance-specific charts"""
        charts_html = ""
        
        try:
            compliance_data = dashboard_data.get('compliance_data', {})
            
            if not compliance_data:
                return "<div class='info-message'>No compliance data available for export.</div>"
            
            # Compliance frameworks overview
            framework_stats = {}
            for framework, findings in compliance_data.items():
                if findings:
                    status_counts = {}
                    for finding in findings:
                        status = finding.get('STATUS', 'UNKNOWN')
                        status_counts[status] = status_counts.get(status, 0) + 1
                    framework_stats[framework] = status_counts
            
            if framework_stats:
                charts_html += self._generate_compliance_overview_chart(framework_stats)
            
        except Exception as e:
            logger.error(f"Failed to generate compliance charts: {str(e)}")
            charts_html += f"<div class='error-message'>Error generating compliance charts: {str(e)}</div>"
        
        return charts_html
    
    def _generate_status_chart(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate status distribution pie chart"""
        try:
            summary_stats = dashboard_data.get('summary_stats', {})
            status_data = summary_stats.get('by_status', {})
            
            if not status_data:
                return ""
            
            fig = go.Figure(data=[go.Pie(
                labels=list(status_data.keys()),
                values=list(status_data.values()),
                hole=0.4,
                marker_colors=[self.colors.get(status.lower(), '#cccccc') for status in status_data.keys()],
                textinfo='label+percent',
                textfont_size=14
            )])
            
            fig.update_layout(
                title="Findings Status Distribution",
                title_font_size=18,
                showlegend=True,
                width=500,
                height=400
            )
            
            chart_html = plot(fig, include_plotlyjs='inline', output_type='div', config={'displayModeBar': False})
            return f'<div class="chart-container">{chart_html}</div>'
            
        except Exception as e:
            logger.error(f"Failed to generate status chart: {str(e)}")
            return ""
    
    def _generate_severity_chart(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate severity distribution bar chart"""
        try:
            summary_stats = dashboard_data.get('summary_stats', {})
            severity_data = summary_stats.get('by_severity', {})
            
            if not severity_data:
                return ""
            
            # Sort by severity order
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
            sorted_severities = [(s, severity_data.get(s, 0)) for s in severity_order if s in severity_data]
            
            if not sorted_severities:
                return ""
            
            labels, values = zip(*sorted_severities)
            
            fig = go.Figure(data=[go.Bar(
                x=labels,
                y=values,
                marker_color=[self.colors.get(severity.lower(), '#cccccc') for severity in labels],
                text=values,
                textposition='outside'
            )])
            
            fig.update_layout(
                title="Findings by Severity",
                title_font_size=18,
                xaxis_title="Severity",
                yaxis_title="Number of Findings",
                width=600,
                height=400
            )
            
            chart_html = plot(fig, include_plotlyjs='inline', output_type='div', config={'displayModeBar': False})
            return f'<div class="chart-container">{chart_html}</div>'
            
        except Exception as e:
            logger.error(f"Failed to generate severity chart: {str(e)}")
            return ""
    
    def _generate_provider_chart(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate provider distribution chart"""
        try:
            summary_stats = dashboard_data.get('summary_stats', {})
            provider_data = summary_stats.get('by_provider', {})
            
            if not provider_data:
                return ""
            
            fig = go.Figure(data=[go.Pie(
                labels=list(provider_data.keys()),
                values=list(provider_data.values()),
                textinfo='label+value',
                textfont_size=12
            )])
            
            fig.update_layout(
                title="Findings by Cloud Provider",
                title_font_size=18,
                showlegend=True,
                width=500,
                height=400
            )
            
            chart_html = plot(fig, include_plotlyjs='inline', output_type='div', config={'displayModeBar': False})
            return f'<div class="chart-container">{chart_html}</div>'
            
        except Exception as e:
            logger.error(f"Failed to generate provider chart: {str(e)}")
            return ""
    
    def _generate_services_chart(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate top services chart"""
        try:
            summary_stats = dashboard_data.get('summary_stats', {})
            service_data = summary_stats.get('by_service', {})
            
            if not service_data:
                return ""
            
            # Take top 10 services
            top_services = dict(list(service_data.items())[:10])
            
            fig = go.Figure(data=[go.Bar(
                y=list(top_services.keys()),
                x=list(top_services.values()),
                orientation='h',
                marker_color='#3498db',
                text=list(top_services.values()),
                textposition='outside'
            )])
            
            fig.update_layout(
                title="Top Services by Findings Count",
                title_font_size=18,
                xaxis_title="Number of Findings",
                yaxis_title="Service",
                width=700,
                height=500
            )
            
            chart_html = plot(fig, include_plotlyjs='inline', output_type='div', config={'displayModeBar': False})
            return f'<div class="chart-container">{chart_html}</div>'
            
        except Exception as e:
            logger.error(f"Failed to generate services chart: {str(e)}")
            return ""
    
    def _generate_region_chart(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate region distribution chart"""
        try:
            summary_stats = dashboard_data.get('summary_stats', {})
            region_data = summary_stats.get('by_region', {})
            
            if not region_data:
                return ""
            
            fig = go.Figure(data=[go.Bar(
                x=list(region_data.keys()),
                y=list(region_data.values()),
                marker_color='#2ecc71',
                text=list(region_data.values()),
                textposition='outside'
            )])
            
            fig.update_layout(
                title="Findings by Region",
                title_font_size=18,
                xaxis_title="Region",
                yaxis_title="Number of Findings",
                width=700,
                height=400,
                xaxis_tickangle=-45
            )
            
            chart_html = plot(fig, include_plotlyjs='inline', output_type='div', config={'displayModeBar': False})
            return f'<div class="chart-container">{chart_html}</div>'
            
        except Exception as e:
            logger.error(f"Failed to generate region chart: {str(e)}")
            return ""
    
    def _generate_compliance_overview_chart(self, framework_stats: Dict[str, Dict[str, int]]) -> str:
        """Generate compliance frameworks overview chart"""
        try:
            frameworks = list(framework_stats.keys())
            pass_counts = [stats.get('PASS', 0) for stats in framework_stats.values()]
            fail_counts = [stats.get('FAIL', 0) for stats in framework_stats.values()]
            
            fig = go.Figure(data=[
                go.Bar(name='PASS', x=frameworks, y=pass_counts, marker_color=self.colors['pass']),
                go.Bar(name='FAIL', x=frameworks, y=fail_counts, marker_color=self.colors['fail'])
            ])
            
            fig.update_layout(
                title="Compliance Frameworks Status",
                title_font_size=18,
                xaxis_title="Framework",
                yaxis_title="Number of Findings",
                barmode='stack',
                width=800,
                height=500,
                xaxis_tickangle=-45
            )
            
            chart_html = plot(fig, include_plotlyjs='inline', output_type='div', config={'displayModeBar': False})
            return f'<div class="chart-container">{chart_html}</div>'
            
        except Exception as e:
            logger.error(f"Failed to generate compliance overview chart: {str(e)}")
            return ""
    
    def _generate_summary_cards(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate summary statistics cards"""
        try:
            summary_stats = dashboard_data.get('summary_stats', {})
            scan_summary = summary_stats.get('scan_summary', {})
            
            cards_html = f"""
            <div class="summary-cards">
                <div class="summary-card">
                    <div class="card-icon">📊</div>
                    <div class="card-content">
                        <h3>{dashboard_data.get('total_findings', 0)}</h3>
                        <p>Total Findings</p>
                    </div>
                </div>
                <div class="summary-card pass">
                    <div class="card-icon">✅</div>
                    <div class="card-content">
                        <h3>{scan_summary.get('pass_rate', 0)}%</h3>
                        <p>Pass Rate</p>
                    </div>
                </div>
                <div class="summary-card fail">
                    <div class="card-icon">❌</div>
                    <div class="card-content">
                        <h3>{scan_summary.get('fail_rate', 0)}%</h3>
                        <p>Fail Rate</p>
                    </div>
                </div>
                <div class="summary-card critical">
                    <div class="card-icon">🚨</div>
                    <div class="card-content">
                        <h3>{scan_summary.get('critical_findings', 0)}</h3>
                        <p>Critical Findings</p>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="card-icon">☁️</div>
                    <div class="card-content">
                        <h3>{scan_summary.get('providers_scanned', 0)}</h3>
                        <p>Providers</p>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="card-icon">🏢</div>
                    <div class="card-content">
                        <h3>{scan_summary.get('accounts_scanned', 0)}</h3>
                        <p>Accounts</p>
                    </div>
                </div>
            </div>
            """
            
            return cards_html
            
        except Exception as e:
            logger.error(f"Failed to generate summary cards: {str(e)}")
            return ""
    
    def _read_template(self, template_name: str) -> str:
        """Read HTML template file"""
        template_path = self.template_dir / template_name
        
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            logger.warning(f"Template {template_name} not found, using default")
            return self._get_default_template()
    
    def _get_default_template(self) -> str:
        """Get default template if template file doesn't exist"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{{{DASHBOARD_TITLE}}}}</title>
    <style>
        {self._get_base_css()}
    </style>
</head>
<body>
    <div class="container">
        <header class="dashboard-header">
            <h1>🛡️ {{{{DASHBOARD_TITLE}}}}</h1>
            <p class="subtitle">Cloud Security Assessment Results</p>
            <div class="export-info">
                <small>Generated: {{{{EXPORT_TIMESTAMP}}}}</small>
                <small>Total Findings: {{{{TOTAL_FINDINGS}}}}</small>
            </div>
        </header>
        
        {{{{SUMMARY_CARDS}}}}
        
        <div class="charts-section">
            <h2>📈 Security Analysis</h2>
            {{{{CHARTS_CONTENT}}}}
        </div>
        
        <footer class="dashboard-footer">
            <p>Powered by <strong>Prowler</strong> - Cloud Security Assessment Tool</p>
            <p><small>This dashboard is self-contained and works completely offline.</small></p>
        </footer>
    </div>
    
    <script type="application/json" id="dashboard-data">
    {{{{DASHBOARD_DATA}}}}
    </script>
</body>
</html>"""
    
    def _get_base_css(self) -> str:
        """Get base CSS styles for the dashboard"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .dashboard-header {
            text-align: center;
            margin-bottom: 30px;
            padding: 30px 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
        }
        
        .dashboard-header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 15px;
        }
        
        .export-info {
            opacity: 0.8;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .summary-card.pass {
            border-left: 4px solid #54d283;
        }
        
        .summary-card.fail {
            border-left: 4px solid #e67272;
        }
        
        .summary-card.critical {
            border-left: 4px solid #951649;
        }
        
        .card-icon {
            font-size: 2em;
        }
        
        .card-content h3 {
            font-size: 1.8em;
            margin-bottom: 5px;
            color: #2c3e50;
        }
        
        .card-content p {
            color: #7f8c8d;
            font-weight: 500;
        }
        
        .charts-section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .charts-section h2 {
            margin-bottom: 20px;
            color: #2c3e50;
        }
        
        .chart-container {
            margin-bottom: 30px;
            display: flex;
            justify-content: center;
        }
        
        .quick-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card h3 {
            font-size: 2em;
            color: #3498db;
            margin-bottom: 10px;
        }
        
        .navigation-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .nav-card {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            cursor: pointer;
            transition: transform 0.3s ease;
        }
        
        .nav-card:hover {
            transform: translateY(-5px);
        }
        
        .nav-card h2 {
            margin-bottom: 15px;
            color: #2c3e50;
        }
        
        .nav-stats {
            margin-top: 15px;
        }
        
        .stat-pill {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.9em;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .stat-pill.fail {
            background-color: #e67272;
            color: white;
        }
        
        .stat-pill.pass {
            background-color: #54d283;
            color: white;
        }
        
        .stat-pill.info {
            background-color: #3498db;
            color: white;
        }
        
        .dashboard-footer {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            border-top: 1px solid #ecf0f1;
        }
        
        .error-message {
            background-color: #e74c3c;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        
        .info-message {
            background-color: #3498db;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .dashboard-header h1 {
                font-size: 2em;
            }
            
            .summary-cards {
                grid-template-columns: 1fr;
            }
        }
        """
    
    def _generate_error_html(self, error_message: str) -> str:
        """Generate error HTML when export fails"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Export Error</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .error {{ background-color: #e74c3c; color: white; padding: 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="error">
        <h2>Dashboard Export Error</h2>
        <p>{error_message}</p>
        <p>Please check the logs for more details.</p>
    </div>
</body>
</html>"""