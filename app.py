import streamlit as st
from models.bert_utils import EmailAnalyzer
from models.url_classifier import URLClassifier
from utils.threat_intel import ThreatIntelligence
from utils.data_processing import DataProcessor
from components.dashboard import (
    render_sidebar, render_email_upload, render_url_input, render_results,
    render_report_section, render_analysis_history, render_statistics
)
from components.visualization import (

    create_gauge_chart, create_threat_timeline,
    create_threat_summary_pie, create_report_visualization
)
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import numpy as np

# Initialize models with configurable paths
email_model_path = st.session_state.get('email_model_path', None)
url_model_path = st.session_state.get('url_model_path', None)

email_analyzer = EmailAnalyzer(model_path=email_model_path)
url_classifier = URLClassifier(model_path=url_model_path)
threat_intel = ThreatIntelligence()
data_processor = DataProcessor()

# Page config
st.set_page_config(
    page_title="Phishing Detection System",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS with galaxy theme
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(to right, #0f2027, #203a43, #2c5364);
        color: white;
    }
    .stButton>button {
        width: 100%;
        background-color: rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.2);
    }
    .stTextInput>div>div>input {
        background-color: rgba(255, 255, 255, 0.1);
        color: white;
    }
    .stTextArea>div>div>textarea {
        background-color: rgba(255, 255, 255, 0.1);
        color: white;
    }
    .block-container {
        padding-top: 2rem;
    }
    div[data-testid="stDataFrame"] {
        background-color: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        padding: 1rem;
    }
    div[data-testid="stDataFrame"] td {
        color: white !important;
    }
    div[data-testid="stDataFrame"] th {
        color: #80b4ff !important;
    }
    .custom-card {
        background-color: rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    /* Add stars animation */
    @keyframes stars {
        0% { opacity: 0; }
        50% { opacity: 1; }
        100% { opacity: 0; }
    }
    .stars {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;
        background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
        background-size: 50px 50px;
        animation: stars 3s infinite;
    }
</style>
<div class="stars"></div>
""", unsafe_allow_html=True)

# Title
st.title("🛡️ Phishing Detection System")

# Sidebar navigation
page = render_sidebar()


def render_url_analysis_results(url_analysis, threat_data):
    analysis_df = pd.DataFrame({
        'Metric': ['Risk Level', 'Confidence Score', 'Detection Rate', 'Threat Categories'],
        'Value': [
            f"{'❌ High' if url_analysis['is_malicious'] else '✅ Low'}",
            f"{url_analysis['confidence']*100:.2f}%",
            f"🎯 {threat_data['detected_urls']}/{threat_data['total_scans']}",
            f"{'🛡️ ' + ', '.join(threat_data.get('threat_categories', ['None']))}"
        ]
    })

    st.markdown('<div class="custom-card">', unsafe_allow_html=True)
    st.subheader("🔍 URL Analysis Results")
    st.table(analysis_df)
    st.markdown('</div>', unsafe_allow_html=True)

    if 'vendors' in threat_data:
        vendor_df = pd.DataFrame([
            {
                'Security Vendor': f"🛡️ {k}",
                'Detection': '❌ Yes' if v['detected'] else '✅ No'
            }
            for k, v in threat_data['vendors'].items()
        ])

        st.markdown('<div class="custom-card">', unsafe_allow_html=True)
        st.subheader("🔒 Security Vendor Analysis")
        st.table(vendor_df)
        st.markdown('</div>', unsafe_allow_html=True)

def download_data(df, filename):
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">Download CSV File</a>'
    st.markdown(href, unsafe_allow_html=True)

import base64

if page == "Email Analysis":
    uploaded_file, text_input = render_email_upload()

    if uploaded_file is not None:
        content = uploaded_file.getvalue().decode()
    elif text_input:
        content = text_input
    else:
        content = None

    if content:
        with st.spinner("Analyzing email..."):
            processed_data = data_processor.process_email(content)
            email_results = email_analyzer.analyze_email(processed_data['clean_content'])

            url_results = []
            for url in processed_data['urls']:
                url_analysis = url_classifier.predict_url(url)
                threat_data = threat_intel.check_url(url)
                url_results.append({
                    'url': url,
                    'analysis': url_analysis,
                    'threat_intel': threat_data
                })

            
                ('Email Analysis', 
                         email_results['is_phishing'],
                         email_results['confidence']*100)
            
            results_df = pd.DataFrame({
                'Metric': ['Phishing Risk', 'Confidence Score', 'URLs Found', 'Suspicious URLs'],
                'Value': [
                    f"{'❌ High' if email_results['is_phishing'] else '✅ Low'}",
                    f"{email_results['confidence']*100:.2f}%",
                    f"🔗 {len(processed_data['urls'])}",
                    f"⚠️ {sum(1 for url in url_results if url['analysis']['is_malicious'])}"
                ]
            })

            st.markdown('<div class="custom-card">', unsafe_allow_html=True)
            st.subheader("📊 Analysis Results")
            st.table(results_df)
            st.markdown('</div>', unsafe_allow_html=True)

            if url_results:
                st.markdown('<div class="custom-card">', unsafe_allow_html=True)
                st.subheader("🔗 URL Analysis")
                urls_df = pd.DataFrame([
                    {
                        'URL': r['url'],
                        'Risk Level': f"{'❌ High' if r['analysis']['is_malicious'] else '✅ Low'}",
                        'Confidence': f"{r['analysis']['confidence']*100:.2f}%",
                        'Threat Categories': ', '.join(r['threat_intel'].get('threat_categories', ['None']))
                    }
                    for r in url_results
                ])
                st.table(urls_df)
                st.markdown('</div>', unsafe_allow_html=True)

elif page == "URL Analysis":
    url = render_url_input()

    if url:
        with st.spinner("Analyzing URL..."):
            url_analysis = url_classifier.predict_url(url)
            threat_data = threat_intel.check_url(url)
            
            # Add to history
            ('URL Analysis',
                         url_analysis['is_malicious'],
                         url_analysis['confidence']*100)

            # Main Analysis Card
            render_url_analysis_results(url_analysis, threat_data)

            # Additional Visualizations
            st.subheader("📊 Analysis Visualizations")

            col1, col2 = st.columns(2)

            with col1:
                # Confidence Gauge Chart
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=url_analysis['confidence'] * 100,
                    title={'text': "Confidence Score"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 33], 'color': "lightgreen"},
                            {'range': [33, 66], 'color': "yellow"},
                            {'range': [66, 100], 'color': "red"}
                        ]
                    }
                ))
                fig_gauge.update_layout(height=300)
                st.plotly_chart(fig_gauge, use_container_width=True)

            with col2:
                # Vendor Detection Distribution
                if 'vendors' in threat_data and threat_data['vendors']:
                    detected = sum(1 for v in threat_data['vendors'].values() if v['detected'])
                    not_detected = len(threat_data['vendors']) - detected

                    fig_pie = go.Figure(data=[go.Pie(
                        labels=['Detected as Malicious', 'Clean'],
                        values=[detected, not_detected],
                        hole=.3,
                        marker_colors=['#ff4b4b', '#00cc00']
                    )])
                    fig_pie.update_layout(
                        title="Vendor Detection Distribution",
                        height=300
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)

            # Historical Threat Data
            st.subheader("📈 Historical Threat Activity")

            # Generate sample historical data
            dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
            historical_data = pd.DataFrame({
                'Date': dates,
                'Detected Threats': np.random.randint(0, 10, 30),
                'Risk Score': np.random.uniform(0, 1, 30) * 100
            })

            fig_line = go.Figure()
            fig_line.add_trace(go.Scatter(
                x=historical_data['Date'],
                y=historical_data['Detected Threats'],
                name='Detected Threats',
                line=dict(color='#ff4b4b')
            ))
            fig_line.add_trace(go.Scatter(
                x=historical_data['Date'],
                y=historical_data['Risk Score'],
                name='Risk Score',
                line=dict(color='#00cc00'),
                yaxis='y2'
            ))

            fig_line.update_layout(
                title='30-Day Threat History',
                xaxis=dict(title='Date'),
                yaxis=dict(title='Detected Threats'),
                yaxis2=dict(title='Risk Score', overlaying='y', side='right'),
                height=400,
                showlegend=True
            )

            st.plotly_chart(fig_line, use_container_width=True)
            st.markdown("📥 Download Historical Data:")
            download_data(historical_data, "threat_history.csv")

elif page == "Threat Intel":
    st.header("Threat Intelligence Dashboard")

    # Create columns for the layout
    left_col, right_col = st.columns([2, 1])

    with left_col:
        threat_stats = threat_intel.get_threat_stats('24h')
        st.plotly_chart(create_threat_timeline(threat_stats, '24h'), use_container_width=True)

    with right_col:
        st.subheader("Live Threat Feed")
        metrics_df = pd.DataFrame({
            'Metric': ['Active Threats', 'Phishing Attempts', 'Malicious URLs'],
            'Count': [
                threat_stats['total_threats'],
                threat_stats['phishing_attempts'],
                threat_stats['malicious_urls']
            ]
        })
        st.table(metrics_df)

    # Additional time windows
    tab1, tab2 = st.tabs(["7 Days View", "30 Days View"])

    with tab1:
        weekly_stats = threat_intel.get_threat_stats('7d')
        st.plotly_chart(create_threat_timeline(weekly_stats, '7d'), use_container_width=True)

    with tab2:
        monthly_stats = threat_intel.get_threat_stats('30d')
        st.plotly_chart(create_threat_timeline(monthly_stats, '30d'), use_container_width=True)

elif page == "History":
    render_analysis_history()

elif page == "Statistics":
    render_statistics()

elif page == "Report":
    report_type = render_report_section()

    if st.button("Generate Report"):
        with st.spinner("Generating comprehensive report..."):
            report_data = None

            if report_type == "Email Analysis Report":
                email_content = "Sample suspicious email content for analysis"
                processed_data = data_processor.process_email(email_content)
                email_results = email_analyzer.analyze_email(processed_data['clean_content'])

                url_results = []
                for url in processed_data['urls']:
                    url_analysis = url_classifier.predict_url(url)
                    threat_data = threat_intel.check_url(url)
                    url_results.append({
                        'url': url,
                        'analysis': url_analysis,
                        'threat_intel': threat_data
                    })

                report_data = threat_intel.generate_report({
                    'email_analysis': email_results,
                    'url_results': url_results
                }, 'email_analysis')

            elif report_type == "URL Analysis Report":
                url_analysis = url_classifier.predict_url("https://example.com")
                threat_data = threat_intel.check_url("https://example.com")

                report_data = threat_intel.generate_report({
                    'url_analysis': url_analysis,
                    'threat_intel': threat_data
                }, 'url_analysis')

            else:
                stats_24h = threat_intel.get_threat_stats('24h')
                stats_7d = threat_intel.get_threat_stats('7d')
                stats_30d = threat_intel.get_threat_stats('30d')

                report_data = threat_intel.generate_report({
                    '24h': stats_24h,
                    '7d': stats_7d,
                    '30d': stats_30d
                }, 'threat_intel')

            if report_data:
                # create_report_visualization returns HTML — render as unsafe HTML
                st.markdown(create_report_visualization(report_data), unsafe_allow_html=True)

                col1, col2 = st.columns(2)
                with col1:
                    if report_type == "Threat Intelligence Report":
                        st.plotly_chart(create_threat_timeline(threat_intel.get_threat_stats('24h'), '24h'))
                    else:
                        st.plotly_chart(create_gauge_chart(
                            report_data['summary']['confidence'] / 100 if 'confidence' in report_data['summary'] else 0.5,
                            f"Risk Score - {report_type}"
                        ))
                with col2:
                    st.plotly_chart(create_threat_summary_pie(threat_intel.get_threat_stats('24h')))

# Footer
st.markdown("---")
st.markdown("Made with ❤️ by AI Security Team")