import pandas as pd
import os
from dotenv import load_dotenv
import sys  # Import sys for sys.exit
from pymongo import MongoClient  # Import MongoClient
from scipy.stats import percentileofscore

# Load environment variables
load_dotenv()

def connect_to_mongo(collection_name):
    """Connect to the MongoDB collection."""
    try:
        mongo_url = os.getenv("MONGO_URL")  # Get MongoDB URL from environment variable
        client = MongoClient(mongo_url)
        db = client["DiplomaThesis"]
        collection = db[collection_name]
        return collection
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}")
        sys.exit(1) 

def get_new_repo_data(repo_name, collection):
    """Fetch the document for the new repository."""
    new_repo_data = collection.find_one({"repo_name": repo_name})
    if not new_repo_data:
        print(f"No data found for repository: {repo_name}")
        sys.exit(1)
    return new_repo_data

def get_repo_name(repo_url):
    """Extract the repository name from the URL."""
    return repo_url.split('/')[-1].replace('.git', '')

def calculate_percentile(value, data):
    """Calculate the percentile of a value within a dataset."""
    try:
        return percentileofscore(data, value, kind='strict')
    except Exception as e:
        print(f"Error calculating percentile: {e}")
        return None

# Load CSV data
csv_path = os.getenv("CSV_PATH")
if not csv_path or not os.path.exists(csv_path):
    print("CSV path is invalid or missing.")
    sys.exit(1)

data = pd.read_csv(csv_path)

# Clean column names
data.columns = data.columns.str.strip()

# Ensure numeric columns are cleaned
columns_to_analyze = ['Total Repo Leaks', 'Guarddog findings', 'Safety findings', 
                      'Critical Vulns', 'High Vulns', 'Medium Vulns', 'Low Vulns']
for col in columns_to_analyze:
    data[col] = pd.to_numeric(data[col], errors='coerce').fillna(0)

# Ensure 'Guarddog findings' column handles specific edge cases
data['Guarddog findings'] = data['Guarddog findings'].replace('No requirements.txt', 0)

# Validate script input
if len(sys.argv) < 2:
    print("Usage: python csv_handler.py <repo_url>")
    sys.exit(1)

repo_url = sys.argv[1]
repo_name = get_repo_name(repo_url)

# Connect to MongoDB and fetch new repository data
collection = connect_to_mongo("final_results")
new_repo_data = get_new_repo_data(repo_name, collection)

def safe_int_conversion(value):
    """Convert a value to int, handling non-numeric strings."""
    if isinstance(value, str) and value == 'No requirements.txt':
        return 0  # or any default value
    try:
        return int(value)
    except ValueError:
        return 0


# Extract findings for the new repository
try:
    new_critical_vulns = safe_int_conversion(new_repo_data.get('critical_vulns', 0))
    new_high_vulns = safe_int_conversion(new_repo_data.get('high_vulns', 0))
    new_medium_vulns = safe_int_conversion(new_repo_data.get('medium_vulns', 0))
    new_low_vulns = safe_int_conversion(new_repo_data.get('low_vulns', 0))
    new_guarddog_findings = safe_int_conversion(new_repo_data.get('guarddog_findings', 0))
    new_safety_findings = safe_int_conversion(new_repo_data.get('safety_findings', 0))
    new_leaks = safe_int_conversion(new_repo_data.get('counter', 0))
except ValueError as e:
    print(f"Error converting MongoDB data: {e}")
    sys.exit(1)

# Debugging print statements
print(f"Critical Vulns: {new_critical_vulns}")
print(f"High Vulns: {new_high_vulns}")
print(f"Medium Vulns: {new_medium_vulns}")
print(f"Low Vulns: {new_low_vulns}")
print(f"Guarddog Findings: {new_guarddog_findings}")
print(f"Safety Findings: {new_safety_findings}")
print(f"Total Repo Leaks: {new_leaks}")

# Calculate percentiles for the new repository
critical_vulns_percentile = calculate_percentile(new_critical_vulns, data['Critical Vulns'])
high_vulns_percentile = calculate_percentile(new_high_vulns, data['High Vulns'])
medium_vulns_percentile = calculate_percentile(new_medium_vulns, data['Medium Vulns'])
low_vulns_percentile = calculate_percentile(new_low_vulns, data['Low Vulns'])
guarddog_findings_percentile = calculate_percentile(new_guarddog_findings, data['Guarddog findings'])
safety_findings_percentile = calculate_percentile(new_safety_findings, data['Safety findings'])
leaks_percentile = calculate_percentile(new_leaks, data['Total Repo Leaks'])

# Print percentiles
print(f"Percentile for Critical Vulns: {critical_vulns_percentile}%")
print(f"Percentile for High Vulns: {high_vulns_percentile}%")
print(f"Percentile for Medium Vulns: {medium_vulns_percentile}%")
print(f"Percentile for Low Vulns: {low_vulns_percentile}%")
print(f"Percentile for Guarddog Findings: {guarddog_findings_percentile}%")
print(f"Percentile for Safety Findings: {safety_findings_percentile}%")
print(f"Percentile for Gitleaks Findings: {leaks_percentile}%")

# Calculate the total score
total_score = 100 - (
    critical_vulns_percentile * 0.2 + 
    high_vulns_percentile * 0.2 + 
    medium_vulns_percentile * 0.05 + 
    low_vulns_percentile * 0.05 + 
    guarddog_findings_percentile * 0.1 + 
    safety_findings_percentile * 0.1 + 
    leaks_percentile * 0.3
)

print(f"Total Score: {total_score}%")






