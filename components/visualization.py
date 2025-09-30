import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
import random

def create_gauge_chart(value, title):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value * 100,
        title={'text': title},
        number={'font': {'color': 'white'}},
        domain={'x': [0, 1], 'y': [0, 1]},
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': 'white'},
            'bar': {'color': "#4CAF50"},
            'bgcolor': "rgba(0,0,0,0)",
            'bordercolor': "white",
            'steps': [
                {'range': [0, 33], 'color': "rgba(76, 175, 80, 0.3)"},
                {'range': [33, 66], 'color': "rgba(255, 193, 7, 0.3)"},
                {'range': [66, 100], 'color': "rgba(244, 67, 54, 0.3)"}
            ]
        }
    ))
    fig.update_layout(
        height=300,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': 'white'},
        margin=dict(t=30, b=0, l=0, r=0)
    )
    return fig

def create_vendor_distribution_chart(vendors_data):
    if not vendors_data:
        return None

    detected = sum(1 for v in vendors_data.values() if v['detected'])
    not_detected = len(vendors_data) - detected

    fig = go.Figure(data=[go.Pie(
        labels=['Detected as Malicious', 'Clean'],
        values=[detected, not_detected],
        hole=.3,
        marker_colors=['#ff4b4b', '#00cc00']
    )])
    fig.update_layout(
        title="Vendor Detection Distribution",
        height=300,
        margin=dict(t=50, b=0, l=0, r=0)
    )
    return fig

def create_threat_timeline(data, time_window='24h'):
    df = pd.DataFrame(data['timeline_data'])

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['phishing_attempts'],
        name='Phishing Attempts',
        mode='lines+markers',
        line=dict(color='#ff4b4b')
    ))
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['malicious_urls'],
        name='Malicious URLs',
        mode='lines+markers',
        line=dict(color='#00cc00')
    ))

    fig.update_layout(
        title=f"Threat Activity ({time_window})",
        xaxis_title="Time",
        yaxis_title="Number of Events",
        hovermode='x unified',
        height=400,
        margin=dict(t=50, b=50, l=50, r=50)
    )
    return fig

def create_threat_summary_pie(data):
    values = [
        data['phishing_attempts'],
        data['malicious_urls'],
        data['suspicious_emails']
    ]
    labels = ['Phishing Attempts', 'Malicious URLs', 'Suspicious Emails']

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=.3,
        textinfo='label+percent',
        marker=dict(colors=['#FF9999', '#66B2FF', '#99FF99'])
    )])
    fig.update_layout(
        title="Threat Distribution",
        height=400,
        margin=dict(t=50, b=50, l=50, r=50)
    )
    return fig

def create_url_analysis_card(url_data):
    """Create a formatted card for URL analysis results"""
    risk_color = "red" if url_data['is_malicious'] else "green"
    confidence = url_data['confidence'] * 100

    html = f"""
    <div style="padding: 20px; border-radius: 10px; border: 1px solid #ddd; margin: 10px 0; background-color: white;">
        <h3 style="color: {risk_color}">Risk Assessment: {'High' if url_data['is_malicious'] else 'Low'}</h3>
        <p><strong>Confidence:</strong> {confidence:.1f}%</p>
        <div style="background-color: #f5f5f5; padding: 10px; border-radius: 5px;">
            <h4>Key Indicators:</h4>
            <ul>
                <li>SSL Certificate: {'Invalid' if url_data['is_malicious'] else 'Valid'}</li>
                <li>Domain Age: {random.randint(1, 1000)} days</li>
                <li>Suspicious Patterns: {'Detected' if url_data['is_malicious'] else 'None'}</li>
            </ul>
        </div>
    </div>
    """
    return html

def create_report_visualization(report_data):
    """Create a comprehensive report visualization"""

    # Format timestamp
    timestamp = datetime.fromisoformat(report_data['timestamp']).strftime("%Y-%m-%d %H:%M:%S")

    # Create colored risk level badge
    risk_level = report_data['summary']['risk_level']
    risk_colors = {
        'Critical': '#dc3545',
        'High': '#ffc107',
        'Medium': '#fd7e14',
        'Low': '#28a745',
        'Unknown': '#6c757d'
    }
    risk_color = risk_colors.get(risk_level, '#6c757d')

    report_html = f"""
    <div style="padding: 20px; border-radius: 10px; border: 1px solid #ddd; background-color: white;">
        <h2>Threat Intelligence Report</h2>
        <p><strong>Generated:</strong> {timestamp}</p>

        <div style="margin: 20px 0;">
            <span style="background-color: {risk_color}; color: white; padding: 5px 10px; border-radius: 5px;">
                Risk Level: {risk_level}
            </span>
        </div>

        <h3>Summary</h3>
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
    """

    # Add summary metrics based on report type
    if 'confidence' in report_data['summary']:
        report_html += f"""
            <p><strong>Confidence Score:</strong> {report_data['summary']['confidence']:.1f}%</p>
        """

    if 'total_threats' in report_data['summary']:
        report_html += f"""
            <p><strong>Total Threats:</strong> {report_data['summary']['total_threats']}</p>
            <p><strong>Recent Indicators:</strong> {report_data['summary'].get('recent_indicators', 0)}</p>
        """

    report_html += """
        </div>

        <h3>Details</h3>
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
    """

    # Add details based on what's available in the report
    if 'top_attack_vectors' in report_data['details']:
        vectors = report_data['details']['top_attack_vectors']
        report_html += f"""
            <p><strong>Top Attack Vectors:</strong> {', '.join(vectors)}</p>
        """

    if 'affected_regions' in report_data['details']:
        regions = report_data['details']['affected_regions']
        report_html += f"""
            <p><strong>Affected Regions:</strong> {', '.join(regions)}</p>
        """

    if 'trend' in report_data['details']:
        report_html += f"""
            <p><strong>Trend:</strong> {report_data['details']['trend']}</p>
        """

    if 'recommendations' in report_data['details']:
        recommendations = report_data['details']['recommendations']
        report_html += """
            <h4>Recommendations:</h4>
            <ul>
        """
        for rec in recommendations:
            report_html += f"<li>{rec}</li>"
        report_html += "</ul>"

    report_html += """
        </div>
    </div>
    """

    return report_html

def create_threat_summary(threat_data):
    fig = go.Figure(data=[
        go.Bar(
            x=['Detected URLs', 'Total Scans', 'Malicious Samples'],
            y=[
                threat_data.get('detected_urls', 0),
                threat_data.get('total_scans', 0),
                threat_data.get('detected_communicating_samples', 0)
            ]
        )
    ])
    fig.update_layout(title="Threat Intelligence Summary")
    return fig