# config.py
import os

# 🔐 Wazuh API Settings
WAZUH_URL = "https://10.118.20.164:55000"  #Change this ip when you have test it
WAZUH_USER = "wazuh_user"
WAZUH_PASSWORD = "wazuh"  # 🔴 CHANGE ME!
VERIFY_SSL = False

# 📁 Paths
# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Data directories
DATA_DIR = os.path.join(BASE_DIR, 'data')
INCIDENTS_DIR = os.path.join(DATA_DIR, 'incidents')  # Where your .json files go
DIAGRAMS_DIR = os.path.join(BASE_DIR, 'diagrams')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

# Customers file
CUSTOMERS_FILE = os.path.join(DATA_DIR, 'customers.json')

# Create folders
for path in [DATA_DIR, INCIDENTS_DIR, DIAGRAMS_DIR, REPORTS_DIR]:
    os.makedirs(path, exist_ok=True)

# 🎨 App Info
APP_TITLE = "DAN LogSight AI 🔍"
COMPANY_LOGO = "https://i.imgur.com/9XK7V0P.png"