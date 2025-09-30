import requests
import hashlib
import time
import random
from datetime import datetime, timedelta
import pandas as pd

class ThreatIntelligence:
    def __init__(self):
        self.vt_api_key = "YOUR_VIRUSTOTAL_API_KEY"
        self.vt_base_url = "https://www.virustotal.com/vtapi/v2"
        self.threat_data_cache = self._initialize_threat_data()
        self.attack_types = [
            'Phishing', 'Malware', 'Ransomware', 'DDoS', 
            'SQL Injection', 'XSS', 'Credential Stuffing'
        ]
        self.regions = [
            'North America', 'Europe', 'Asia Pacific', 
            'South America', 'Africa', 'Middle East'
        ]

    def _initialize_threat_data(self):
        now = datetime.now()
        dates = [now - timedelta(hours=x) for x in range(24*30)]

        data = {
            'timestamp': dates,
            'phishing_attempts': [random.randint(10, 100) for _ in dates],
            'malicious_urls': [random.randint(5, 50) for _ in dates],
            'suspicious_emails': [random.randint(20, 150) for _ in dates],
            'ransomware_attacks': [random.randint(1, 20) for _ in dates],
            'ddos_attempts': [random.randint(5, 30) for _ in dates],
            'data_breaches': [random.randint(1, 10) for _ in dates]
        }
        return pd.DataFrame(data)

    def get_threat_stats(self, time_window='24h'):
        now = datetime.now()
        if time_window == '24h':
            cutoff = now - timedelta(hours=24)
        elif time_window == '7d':
            cutoff = now - timedelta(days=7)
        elif time_window == '30d':
            cutoff = now - timedelta(days=30)
        else:
            cutoff = now - timedelta(hours=24)

        filtered_data = self.threat_data_cache[self.threat_data_cache['timestamp'] >= cutoff]

        if filtered_data.empty:
            return {
                'total_threats': 0,
                'phishing_attempts': 0,
                'malicious_urls': 0,
                'suspicious_emails': 0,
                'ransomware_attacks': 0,
                'ddos_attempts': 0,
                'data_breaches': 0,
                'timeline_data': [],
                'top_attack_vectors': [],
                'affected_regions': []
            }

        stats = {
            'total_threats': len(filtered_data),
            'phishing_attempts': int(filtered_data['phishing_attempts'].sum()),
            'malicious_urls': int(filtered_data['malicious_urls'].sum()),
            'suspicious_emails': int(filtered_data['suspicious_emails'].sum()),
            'ransomware_attacks': int(filtered_data['ransomware_attacks'].sum()),
            'ddos_attempts': int(filtered_data['ddos_attempts'].sum()),
            'data_breaches': int(filtered_data['data_breaches'].sum()),
            'timeline_data': filtered_data.to_dict('records'),
            'top_attack_vectors': self._get_top_attack_vectors(),
            'affected_regions': self._get_affected_regions()
        }

        return stats
    def generate_report(self, data, report_type='threat_intel'):
        """Generate a detailed report based on type"""
        try:
            if report_type == 'email_analysis':
                return self._generate_email_report(data)
            elif report_type == 'url_analysis':
                return self._generate_url_report(data)
            else:
                return self._generate_threat_intel_report(data)
        except Exception as e:
            print(f"Error generating report: {str(e)}")
            return self._generate_fallback_report()

    def _generate_email_report(self, data):
        """Generate email analysis report"""
        email_results = data.get('email_analysis', {})
        url_results = data.get('url_results', [])

        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'risk_level': 'High' if email_results.get('is_phishing', False) else 'Low',
                'confidence': email_results.get('confidence', 0) * 100,
                'urls_found': len(url_results),
                'malicious_urls': sum(1 for url in url_results if url['analysis'].get('is_malicious', False))
            },
            'details': {
                'phishing_indicators': self._get_phishing_indicators(),
                'url_analysis': [
                    {
                        'url': url['url'],
                        'risk_level': 'High' if url['analysis'].get('is_malicious', False) else 'Low',
                        'confidence': url['analysis'].get('confidence', 0) * 100
                    } for url in url_results
                ],
                'recommendations': self._generate_recommendations()
            }
        }

    def _generate_url_report(self, data):
        """Generate URL analysis report"""
        url_analysis = data.get('url_analysis', {})
        threat_intel = data.get('threat_intel', {})

        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'risk_level': 'High' if url_analysis.get('is_malicious', False) else 'Low',
                'confidence': url_analysis.get('confidence', 0) * 100,
                'total_scans': threat_intel.get('total_scans', 0),
                'detected_urls': threat_intel.get('detected_urls', 0)
            },
            'details': {
                'threat_categories': threat_intel.get('threat_categories', []),
                'vendor_analysis': threat_intel.get('vendors', {}),
                'recommendations': self._generate_recommendations()
            }
        }

    def _generate_threat_intel_report(self, time_periods):
        """Generate threat intelligence report"""
        total_threats = sum(stats['total_threats'] for stats in time_periods.values())
        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_threats': total_threats,
                'risk_level': self._calculate_risk_level(total_threats),
                'recent_indicators': sum(period['phishing_attempts'] for period in time_periods.values()),
                'threat_distribution': {
                    'phishing': sum(period['phishing_attempts'] for period in time_periods.values()),
                    'malicious_urls': sum(period['malicious_urls'] for period in time_periods.values()),
                    'ransomware': sum(period['ransomware_attacks'] for period in time_periods.values()),
                    'ddos': sum(period['ddos_attempts'] for period in time_periods.values())
                }
            },
            'details': {
                'top_attack_vectors': self._get_top_attack_vectors(),
                'affected_regions': self._get_affected_regions(),
                'trend': self._calculate_trend(time_periods),
                'recommendations': self._generate_recommendations()
            }
        }

    def _get_phishing_indicators(self):
        """Generate sample phishing indicators"""
        indicators = [
            "Suspicious sender domain",
            "Urgent action required",
            "Request for sensitive information",
            "Grammatical errors",
            "Mismatched URLs",
            "Generic greeting",
            "Suspicious attachments"
        ]
        return random.sample(indicators, k=3)

    def _calculate_risk_level(self, total_threats):
        if total_threats > 1000:
            return 'Critical'
        elif total_threats > 500:
            return 'High'
        elif total_threats > 100:
            return 'Medium'
        else:
            return 'Low'

    def _calculate_trend(self, time_periods):
        if '24h' in time_periods and '7d' in time_periods:
            recent = time_periods['24h']['total_threats']
            previous = time_periods['7d']['total_threats'] / 7
            if recent > previous * 1.2:
                return 'Increasing'
            elif recent < previous * 0.8:
                return 'Decreasing'
            else:
                return 'Stable'
        return 'Unknown'

    def _generate_recommendations(self):
        recommendations = [
            "Implement multi-factor authentication",
            "Update security patches regularly",
            "Conduct regular security training",
            "Monitor unusual login attempts",
            "Implement network segmentation",
            "Regular backup of critical data",
            "Deploy endpoint protection",
            "Use email filtering solutions",
            "Enable DMARC/SPF/DKIM",
            "Implement URL filtering"
        ]
        return random.sample(recommendations, k=3)

    def _get_top_attack_vectors(self):
        return random.sample(self.attack_types, k=min(5, len(self.attack_types)))

    def _get_affected_regions(self):
        return random.sample(self.regions, k=min(4, len(self.regions)))

    def _generate_fallback_report(self):
        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_threats': 0,
                'risk_level': 'Unknown',
                'recent_indicators': 0
            },
            'details': {
                'top_attack_vectors': [],
                'affected_regions': [],
                'trend': 'Unknown',
                'error': 'Failed to generate detailed report'
            }
        }

    def check_url(self, url):
        return {
            'detected_urls': random.randint(0, 10),
            'total_scans': 70,
            'scan_date': datetime.now().isoformat(),
            'risk_level': random.choice(['Low', 'Medium', 'High']),
            'threat_categories': random.sample(self.attack_types, k=2),
            'vendors': {
                f'vendor_{i}': {'detected': random.choice([True, False])}
                for i in range(1, 6)
            }
        }

    def check_domain(self, domain):
        return {
            'detected_urls': random.randint(0, 20),
            'detected_communicating_samples': random.randint(0, 15),
            'total_scans': random.randint(50, 100),
            'categories': random.sample(self.attack_types, k=2)
        }