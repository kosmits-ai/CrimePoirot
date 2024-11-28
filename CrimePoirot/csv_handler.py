import pandas as pd
import os
from dotenv import load_dotenv
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import sys  # Import sys for sys.exit
from pymongo import MongoClient  # Import MongoClient
from scipy.stats import percentileofscore
import mongo_handler
import main

def connect_to_mongo(collection_name):
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
    # Fetch the document for the new repository
    new_repo_data = collection.find_one({"repo_name": repo_name})
    return new_repo_data


def get_repo_name(repo_url):
    """Extract the repository name from the URL."""
    return repo_url.split('/')[-1].replace('.git', '')

# percentage of data points in the list that are less than or equal to the given value.
def calculate_percentile(value, data):
        return percentileofscore(data, value, kind='rank')



#Data processing
load_dotenv()
csv_path = os.getenv("CSV_PATH")

data = pd.read_csv(csv_path)

data['Low Vulns'] = pd.to_numeric(data['Low Vulns'], errors='coerce').fillna(0).astype(int)

# Replace "No requirements.txt" with 0
data['Guarddog findings'] = data['Guarddog findings'].replace('No requirements.txt', 0)

# Convert the column to numeric
data['Guarddog findings'] = pd.to_numeric(data['Guarddog findings'], errors='coerce')


# Plot the histogram with smaller bins for finer scaling

from scipy.stats import gaussian_kde

# Strip and inspect column names
data.columns = data.columns.str.strip()

# List of columns to analyze
columns_to_analyze = ['Total Repo Leaks', 'Guarddog findings', 'Safety findings', 'Critical Vulns', 'High Vulns', 'Medium Vulns', 'Low Vulns']


repo_url = sys.argv[1]
    
repo_name = get_repo_name(repo_url)

collection = connect_to_mongo("final_results")

new_repo_data =get_new_repo_data(repo_name, collection)

# Get the findings for the new repository
new_critical_vulns = new_repo_data['critical_vulns']
new_high_vulns = new_repo_data['high_vulns']
new_medium_vulns = new_repo_data['medium_vulns']
new_low_vulns = new_repo_data['low_vulns']
new_guarddog_findings = new_repo_data['guarddog_findings']
new_safety_findings = new_repo_data['safety_findings']
new_leaks = new_repo_data['counter']

print(f"{new_critical_vulns}")
print(f"{new_high_vulns}")
print(f"{new_medium_vulns}")
print(f"{new_low_vulns}")
print(f"{new_guarddog_findings}")
print(f"{new_safety_findings}")
print(f"{new_leaks}")


# Calculate percentiles for features of new repo 
critical_vulns_percentile = calculate_percentile(new_critical_vulns, data['Critical Vulns'])
print(f"Percentile for Critical Vulns: {critical_vulns_percentile}%")

high_vulns_percentile = calculate_percentile(new_high_vulns, data['High Vulns'])
print(f"Percentile for High Vulns: {high_vulns_percentile}%")

medium_vulns_percentile = calculate_percentile(new_medium_vulns, data['Medium Vulns'])
print(f"Percentile for Medium Vulns: {medium_vulns_percentile}%")

low_vulns_percentile = calculate_percentile(new_low_vulns, data['Low Vulns'])
print(f"Percentile for Low Vulns: {low_vulns_percentile}%")


guarddog_findings_percentile = calculate_percentile(new_guarddog_findings, data['Guarddog findings'])
print(f"Percentile for Guarddog Findings: {guarddog_findings_percentile}%")


safety_findings_percentile = calculate_percentile(new_safety_findings, data['Safety findings'])
print(f"Percentile for Safety Findings: {safety_findings_percentile}%")

leaks_percentile = calculate_percentile(new_leaks, data['Total Repo Leaks'])
print(f"Percentile for Gitleaks findings: {leaks_percentile}%")

total_score = 100 - (critical_vulns_percentile *0.2 + high_vulns_percentile * 0.2 + medium_vulns_percentile * 0.05+ low_vulns_percentile *0.05+ guarddog_findings_percentile * 0.1 + safety_findings_percentile *0.1 + leaks_percentile * 0.3)
print(f"Total score: {total_score}%")





