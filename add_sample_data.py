from supabase import create_client
from datetime import datetime
import json

# Load secrets
with open(".streamlit/secrets.toml") as f:
    content = f.read()
    
# Parse manually (simple way)
import re
url = re.search(r'url = "([^"]+)"', content).group(1)
key = re.search(r'key = "([^"]+)"', content).group(1)

# Connect
supabase = create_client(url, key)

# Sample threats data
threats = [
    {"source": "Dark Web Forum", "target_country": "USA", "severity": "Critical", "status": "Active", "description": "Ransomware group targeting US hospitals"},
    {"source": "Paste Site", "target_country": "UK", "severity": "High", "status": "Investigating", "description": "Stolen credit card data dump"},
    {"source": "Telegram Channel", "target_country": "India", "severity": "Critical", "status": "Active", "description": "Banking trojan distribution campaign"},
    {"source": "Dark Web Forum", "target_country": "Germany", "severity": "High", "status": "Active", "description": "Corporate credentials leak"},
    {"source": "IRC Channel", "target_country": "Japan", "severity": "Medium", "status": "Resolved", "description": "Phishing kit distribution"},
    {"source": "Dark Web Market", "target_country": "USA", "severity": "Critical", "status": "Active", "description": "Zero-day exploit for sale"},
    {"source": "Paste Site", "target_country": "India", "severity": "High", "status": "Investigating", "description": "Aadhaar data breach claims"},
    {"source": "Telegram Channel", "target_country": "UK", "severity": "Medium", "status": "Active", "description": "Crypto wallet drainer malware"},
    {"source": "Dark Web Forum", "target_country": "Germany", "severity": "High", "status": "Active", "description": "DDoS-for-hire service advertisement"},
    {"source": "IRC Channel", "target_country": "USA", "severity": "Low", "status": "Resolved", "description": "Spam campaign targeting employees"},
    {"source": "Dark Web Market", "target_country": "India", "severity": "Critical", "status": "Active", "description": "SIM swap service promotion"},
    {"source": "Paste Site", "target_country": "Japan", "severity": "High", "status": "Investigating", "description": "Source code leak from tech company"},
    {"source": "Telegram Channel", "target_country": "UK", "severity": "Medium", "status": "Active", "description": "Fake invoice phishing campaign"},
    {"source": "Dark Web Forum", "target_country": "USA", "severity": "High", "status": "Active", "description": "RDP access marketplace"},
    {"source": "IRC Channel", "target_country": "Germany", "severity": "Low", "status": "Resolved", "description": "Low-quality credential dump"},
    {"source": "Dark Web Market", "target_country": "India", "severity": "High", "status": "Active", "description": "KYC bypass service advertisement"},
    {"source": "Paste Site", "target_country": "USA", "severity": "Medium", "status": "Investigating", "description": "API keys exposure in public repo"},
    {"source": "Telegram Channel", "target_country": "Japan", "severity": "High", "status": "Active", "description": "Mobile banking malware campaign"},
    {"source": "Dark Web Forum", "target_country": "UK", "severity": "Critical", "status": "Active", "description": "Nation-state sponsored APT activity"},
    {"source": "IRC Channel", "target_country": "India", "severity": "Medium", "status": "Resolved", "description": "Old credential stuffing list"},
]

# Insert all
for threat in threats:
    data = {
        **threat,
        "created_at": datetime.now().isoformat()
    }
    supabase.table("threats").insert(data).execute()

print(f"✅ Successfully added {len(threats)} threats to database!")