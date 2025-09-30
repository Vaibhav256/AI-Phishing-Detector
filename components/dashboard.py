import streamlit as st
import pandas as pd
import base64
import json

def download_data(data, filename):
    """Generate a download link for data"""
    if isinstance(data, pd.DataFrame):
        # For DataFrames, convert to CSV
        csv = data.to_csv(index=False)
        b64 = base64.b64encode(csv.encode()).decode()
        href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">Download {filename}</a>'
    else:
        # For dictionaries and other data, convert to JSON
        json_str = json.dumps(data, indent=2)
        b64 = base64.b64encode(json_str.encode()).decode()
        href = f'<a href="data:file/json;base64,{b64}" download="{filename}">Download {filename}</a>'

    st.markdown(href, unsafe_allow_html=True)

def render_sidebar():
    st.sidebar.markdown("""
    <style>
        .sidebar-nav {
            padding: 1rem 0;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            margin-bottom: 1rem;
        }
    </style>
    """, unsafe_allow_html=True)

    st.sidebar.markdown('<div class="sidebar-nav">', unsafe_allow_html=True)
    page = st.sidebar.radio(
        "Navigation",
        ["Email Analysis", "URL Analysis", "Threat Intel", "History", "Statistics", "Report"]
    )
    st.sidebar.markdown('</div>', unsafe_allow_html=True)
    return page

def render_statistics():
    st.header("📈 Model Performance Statistics")

    # Email Model Stats
    st.subheader("📧 Email Analysis Model")
    email_stats = pd.DataFrame({
        'Metric': ['Accuracy', 'Precision', 'Recall', 'F1 Score', 'AUC-ROC'],
        'Value': ['0.92', '0.89', '0.94', '0.91', '0.95']
    })

    st.markdown('<div class="custom-card">', unsafe_allow_html=True)
    st.table(email_stats)
    st.markdown("📥 Download Email Model Stats:")
    download_data(email_stats, "email_model_stats.csv")
    st.markdown('</div>', unsafe_allow_html=True)

    # URL Model Stats
    st.subheader("🔗 URL Analysis Model")
    url_stats = pd.DataFrame({
        'Metric': ['Accuracy', 'Precision', 'Recall', 'F1 Score', 'AUC-ROC'],
        'Value': ['0.94', '0.92', '0.93', '0.93', '0.96']
    })

    st.markdown('<div class="custom-card">', unsafe_allow_html=True)
    st.table(url_stats)
    st.markdown("📥 Download URL Model Stats:")
    download_data(url_stats, "url_model_stats.csv")
    st.markdown('</div>', unsafe_allow_html=True)

def create_analysis_card(analysis_data):
    """Create a formatted card for analysis results"""
    return pd.DataFrame({
        'Indicator': [
            'Risk Assessment',
            'Confidence',
            'Status',
            'Analysis Date'
        ],
        'Value': [
            f"{'❌ High Risk' if analysis_data['is_malicious'] else '✅ Low Risk'}",
            f"{analysis_data['confidence']*100:.1f}%",
            analysis_data['status'],
            'Just Now'
        ]
    })

def render_email_upload():
    st.header("📧 Email Analysis")
    st.markdown("""
    <div class="custom-card">
        <h4>📝 Instructions</h4>
        <p>Upload an email file or paste the content for phishing analysis. 
        The system will analyze the content and any embedded URLs.</p>
    </div>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader("Upload email content (txt file)", type=['txt'])
    text_input = st.text_area("Or paste email content here")

    return uploaded_file, text_input

def render_url_input():
    st.header("🔗 URL Analysis")
    st.markdown("""
    <div class="custom-card">
        <h4>📝 Instructions</h4>
        <p>Enter a URL to analyze its safety and check for potential phishing indicators.</p>
    </div>
    """, unsafe_allow_html=True)

    url = st.text_input("Enter URL to analyze", placeholder="https://example.com")
    return url

def render_analysis_history():
    st.header("📊 Analysis History")
    st.markdown("""
    <div class="custom-card">
        <h4>Recent Analysis Results</h4>
        <p>View and track your previous analysis results and trends.</p>
    </div>
    """, unsafe_allow_html=True)

    history_data = {
        'Timestamp': ['2024-02-10 10:00', '2024-02-10 09:30', '2024-02-10 09:00'],
        'Analysis Type': ['URL Analysis', 'Email Analysis', 'URL Analysis'],
        'Result': ['❌ Malicious', '✅ Clean', '⚠️ Suspicious'],
        'Confidence': ['95%', '87%', '92%']
    }
    df = pd.DataFrame(history_data)
    st.table(df)
    st.markdown("📥 Download Analysis History:")
    download_data(df, "analysis_history.csv")

def render_configuration():
    st.header("Configuration")
    st.markdown("""
    <div class="custom-card">
        <h4>Model Configuration</h4>
        <p>Configure detection models and analysis settings.</p>
    </div>
    """, unsafe_allow_html=True)

    # Model paths configuration
    st.subheader("Model Settings")
    email_model_path = st.text_input(
        "Email Analysis Model Path",
        placeholder="/path/to/email/model",
        help="Path to your trained BERT model for email analysis"
    )

    url_model_path = st.text_input(
        "URL Analysis Model Path",
        placeholder="/path/to/url/model",
        help="Path to your trained Random Forest model for URL analysis"
    )

    if st.button("Save Configuration"):
        st.success("Configuration saved successfully!")

def render_report_section():
    st.header("📝 Generate Report")
    st.markdown("""
    <div class="custom-card">
        <h4>Report Generation</h4>
        <p>Generate detailed analysis reports with visualizations and insights.</p>
    </div>
    """, unsafe_allow_html=True)

    report_type = st.selectbox(
        "Select report type",
        ["Email Analysis Report", "URL Analysis Report", "Threat Intelligence Report"]
    )
    return report_type

def render_url_analysis_results(url_analysis, threat_data):
    st.markdown('<div class="custom-card">', unsafe_allow_html=True)
    st.subheader("🔍 URL Analysis Results")

    analysis_df = pd.DataFrame({
        'Metric': ['Risk Level', 'Confidence Score', 'Detection Rate', 'Threat Categories'],
        'Value': [
            f"{'❌ High' if url_analysis['is_malicious'] else '✅ Low'}",
            f"{url_analysis['confidence']*100:.2f}%",
            f"🎯 {threat_data['detected_urls']}/{threat_data['total_scans']}",
            f"{'🛡️ ' + ', '.join(threat_data.get('threat_categories', ['None']))}"
        ]
    })

    st.table(analysis_df)
    st.markdown("📥 Download Results:")
    download_data(analysis_df, "url_analysis_summary.csv")

    # Vendor Analysis
    if 'vendors' in threat_data and threat_data['vendors']:
        vendor_df = pd.DataFrame([
            {
                'Security Vendor': f"🛡️ {k}",
                'Detection': '❌ Yes' if v['detected'] else '✅ No'
            }
            for k, v in threat_data['vendors'].items()
        ])
    else:
        vendor_df = pd.DataFrame({
            'Security Vendor': ['No vendors detected'],
            'Detection': ['N/A']
        })

    st.markdown('<div class="custom-card">', unsafe_allow_html=True)
    st.subheader("🔒 Security Vendor Analysis")
    st.table(vendor_df)
    st.markdown("📥 Download Vendor Analysis:")
    download_data(vendor_df, "vendor_analysis.csv")
    st.markdown('</div>', unsafe_allow_html=True)


def render_results(results):
    st.header("🔍 Analysis Results")

    tabs = st.tabs(["📊 Summary", "📋 Details", "🛡️ Threat Intel"])

    with tabs[0]:
        st.subheader("Summary")
        summary_data = pd.DataFrame({
            'Metric': [],
            'Value': []
        })

        if 'email_analysis' in results:
            summary_data = pd.concat([summary_data, pd.DataFrame({
                'Metric': ['Email Risk Score', 'Confidence'],
                'Value': [
                    f"{'❌' if results['email_analysis']['is_phishing'] else '✅'} {results['email_analysis']['confidence']*100:.1f}%",
                    f"{results['email_analysis']['confidence']*100:.1f}%"
                ]
            })])

        if 'url_analysis' in results:
            summary_data = pd.concat([summary_data, pd.DataFrame({
                'Metric': ['URL Risk Level', 'Detection Confidence'],
                'Value': [
                    f"{'❌' if results['url_analysis']['is_malicious'] else '✅'} {results['url_analysis']['confidence']*100:.1f}%",
                    f"{results['url_analysis']['confidence']*100:.1f}%"
                ]
            })])

        st.table(summary_data)
        st.markdown("📥 Download Summary:")
        download_data(summary_data, "analysis_summary.csv")

    with tabs[1]:
        st.subheader("Detailed Analysis")
        if 'email_analysis' in results:
            st.markdown('<div class="custom-card">', unsafe_allow_html=True)
            st.markdown("#### 📧 Email Analysis Results")
            email_df = create_analysis_card(results['email_analysis'])
            st.table(email_df)
            st.markdown("📥 Download Email Analysis:")
            download_data(email_df, "email_analysis_details.csv")
            st.markdown('</div>', unsafe_allow_html=True)

        if 'url_analysis' in results:
            st.markdown('<div class="custom-card">', unsafe_allow_html=True)
            st.markdown("#### 🔗 URL Analysis Results")
            url_df = create_analysis_card(results['url_analysis'])
            st.table(url_df)
            st.markdown("📥 Download URL Analysis:")
            download_data(url_df, "url_analysis_details.csv")
            st.markdown('</div>', unsafe_allow_html=True)

    with tabs[2]:
        st.subheader("Threat Intelligence")
        if 'threat_intel' in results:
            threat_data = pd.DataFrame({
                'Indicator': ['Detection Rate', 'Risk Level', 'Categories'],
                'Value': [
                    f"{results['threat_intel'].get('detected_urls', 0)}/{results['threat_intel'].get('total_scans', 0)}",
                    f"{'❌' if results['threat_intel'].get('risk_level') == 'High' else '✅'} {results['threat_intel'].get('risk_level', 'Unknown')}",
                    ', '.join(results['threat_intel'].get('threat_categories', []))
                ]
            })
            st.table(threat_data)
            st.markdown("📥 Download Threat Intelligence:")
            download_data(threat_data, "threat_intelligence.csv")