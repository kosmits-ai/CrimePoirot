import os
import sys
from pymongo import MongoClient
from dotenv import load_dotenv
import csv 

# Load environment variables from .env file
load_dotenv()

# Connect to the MongoDB client
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

def get_repo_name(repo_url):
    """Extract the repository name from the URL."""
    return repo_url.split('/')[-1].replace('.git', '')

def count_leaks(repo_name, collection):
    matching_documents = collection.find(
    {
     "repo_name": repo_name ,
     "RuleID": {"$exists": True}}
    )

    counter = 0
    for doc in matching_documents:
        counter += 1

    print(f"Total leaks in repository: {counter}")
    return counter

def count_current_leaks(repo_name, collection):
    # Use find_one to get a single document
    matching_document = collection.find_one({"repo_name": repo_name})
    
    if matching_document:  # Check if a document is found
        current_leaks = matching_document.get("leaks", 0)
        print(f"Total leaks pushed in current commit: {current_leaks}")
        return current_leaks
    else:
        print(f"No document found for repository: {repo_name}")
        return 0


def count_guarddog_findings(repo_name, collection):
    # Check if there is a document with output_text equal to "No requirements.txt"
    if collection.find_one({"repo_name": repo_name, "output_text": "No requirements.txt"}):
        guarddog_findings = "No requirements.txt"
    else:
        # Count documents that have output_text and are not equal to "No requirements.txt" or 0
        guarddog_findings = collection.count_documents({
            "repo_name": repo_name,
            "output_text": {"$exists": True, "$nin": ["No requirements.txt", 0]}
        })
    
    print(f"Total guarddog findings: {guarddog_findings}")
    return guarddog_findings


def count_safety_findings(repo_name, collection):
    safety_findings = 0
    safety_findings = collection.count_documents({
        "repo_name": repo_name,
        "package_name": {"$exists": True, "$ne": ""} 
    })
    print(f"Total safety findings: {safety_findings}")
    return safety_findings

# Function to count documents and calculate vulnerabilities for a specific repository
def count_vulnerabilities(repo_name, collection):
    # Find a document that matches the repository name
    matching_document = collection.find_one({"repository": repo_name})
    
    # Initialize counters as elements in the list
    total_vulns = [0, 0, 0, 0]  # [total_critical, total_high, total_medium, total_low]

    if matching_document:  # Check if the document exists
        total_vulns[0] += matching_document.get("critical", 0)  # total_critical
        total_vulns[1] += matching_document.get("high", 0)      # total_high
        total_vulns[2] += matching_document.get("medium", 0)    # total_medium
        total_vulns[3] += matching_document.get("low", 0)       # total_low

    # Print the results
    print(f"Repository: {repo_name}")
    print(f"Total critical vulnerabilities: {total_vulns[0]}")
    print(f"Total high vulnerabilities: {total_vulns[1]}")
    print(f"Total medium vulnerabilities: {total_vulns[2]}")
    print(f"Total low vulnerabilities: {total_vulns[3]}")
    
    return total_vulns


def save_to_csv(repo_name, counter, current_leaks, guarddog_findings, safety_findings, total_vulns):
    # File name for the CSV
    csv_file = os.getenv("CSV_PATH")
    
    # Check if the file exists
    file_exists = os.path.isfile(csv_file)
    
    # Open the file in append mode
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        
        # If the file doesn't exist, write the header
        if not file_exists:
            writer.writerow(["Repository","Total Repo Leaks", "Current commit Leaks", "Guarddog Findings", "Safety Findings", "Critical Vulns", "High Vulns", "Medium Vulns", "Low Vulns"])
        
        # Write the data
        writer.writerow([repo_name, counter, current_leaks, guarddog_findings, safety_findings, total_vulns[0], total_vulns[1], total_vulns[2], total_vulns[3]])



# Main execution
if __name__ == "__main__":
    
    repo_url = input("Enter the repository URL: ")
    
    # Connect to MongoDB Atlas and get the collection
    repo_name = get_repo_name(repo_url)
    
    # Connect to the 'bearer_reports' collection
    collection = connect_to_mongo("bearer_reports")

    # Count vulnerabilities for the given repository
    total_vulns = count_vulnerabilities(repo_name, collection)

    collection = connect_to_mongo("gitleaks_reports")

    current_leaks = count_current_leaks(repo_name, collection)
    counter = count_leaks(repo_name, collection)

    collection = connect_to_mongo("guarddog_reports")
    guarddog_findings = count_guarddog_findings(repo_name, collection)

    collection = connect_to_mongo("safety_reports")
    safety_findings = count_safety_findings(repo_name, collection)

    save_to_csv(repo_name, counter, current_leaks, guarddog_findings, safety_findings,total_vulns)
