
import pandas as pd
import re
from urllib.parse import urlparse

def clean_email_content(content):
    # Remove HTML tags
    clean_text = re.sub(r'<[^>]+>', '', content)
    # Remove extra whitespace
    clean_text = ' '.join(clean_text.split())
    return clean_text

def extract_urls_from_email(content):
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, content)

def parse_email_metadata(email_content):
    metadata = {}
    try:
        # Extract basic email metadata
        headers = email_content.split('\n\n')[0]
        metadata['from'] = re.findall(r'From: (.*)', headers)
        metadata['subject'] = re.findall(r'Subject: (.*)', headers)
        metadata['date'] = re.findall(r'Date: (.*)', headers)
    except Exception:
        pass
    return metadata

class DataProcessor:
    def __init__(self):
        pass
        
    def process_email(self, content):
        clean_content = clean_email_content(content)
        urls = extract_urls_from_email(content)
        metadata = parse_email_metadata(content)
        
        return {
            'clean_content': clean_content,
            'urls': urls,
            'metadata': metadata
        }
