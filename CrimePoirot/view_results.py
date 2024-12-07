import os
import sys
from pymongo import MongoClient
from dotenv import load_dotenv

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


if __name__ == "__main__":
    repo_url = sys.argv[1]
    repo_name = get_repo_name(repo_url)

    collection = connect_to_mongo("gitleaks_reports")
    matching_document = collection.find_one({"repo_name": repo_name, "leaks": 0})
    if matching_document:
        print(f"No leaks found for repository: {repo_name}")
        print()
    else:
        gitleaks_findings = collection.find({"repo_name": repo_name})
        print(f"Credentials leaked found by Gitleaks:")
        print()
        for doc in gitleaks_findings:
            print(f"Description: {doc.get('Description', 'N/A')}")
            print(f"File: {doc.get('File', 'N/A')}")
            print(f"Starting line: {doc.get('StartLine', 'N/A')}")
            print(f"Ending line: {doc.get('EndLine', 'N/A')}")
            print()
        print()

    collection = connect_to_mongo("guarddog_reports")
    matching_document = collection.find_one({"repo_name": repo_name, "output_text":0})
    if matching_document:
        print(f"No malicious indications found on packages from Guarddog in: {repo_name}")
    else:
        guarddog_findings = collection.find({"repo_name": repo_name})
        for doc in guarddog_findings:
            print(f"Description of malicious indication: {doc.get('output_text', 'N/A')}")
            print(f"Heuristic rule Guarddog based on: {doc.get('rule_id', 'N/A')}")
            print()
        print()

    collection = connect_to_mongo("safety_reports")
    matching_document = collection.find_one({"repo_name": repo_name, "output":0})
    if matching_document:
        print(f"No vulnerable packages found from Safety in: {repo_name}")
    else:
        safety_findings = collection.find({"repo_name": repo_name})
        for doc in safety_findings:
            print(f"Vulnerable package name: {doc.get('package_name', 'N/A')}")
        print()
    
    collection = connect_to_mongo("bearer_reports")
    matching_document = collection.find_one({"repository": repo_name})
    bearer_findings = matching_document.get('vulnerabilities', 'N/A')
    if bearer_findings:
        for doc in bearer_findings:
            print(f"Severity: {doc['severity']}, Description: {doc['description']}")
            print()
    else:
        print("No vulnerabilities found by Bearer.")