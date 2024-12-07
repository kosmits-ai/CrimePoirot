import os
import sys
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def connect_to_mongo(collection_name):
    """
    Connect to a MongoDB collection.
    """
    try:
        mongo_url = os.getenv("MONGO_URL")  # MongoDB URL from environment variable
        client = MongoClient(mongo_url)
        db = client["DiplomaThesis"]
        collection = db[collection_name]
        return collection
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}")
        sys.exit(1)

def get_repo_name(repo_url):
    """
    Extract the repository name from its URL.
    """
    return repo_url.split('/')[-1].replace('.git', '')

def check_findings(collection, repo_name, zero_field, description_fields):
    """
    Check for findings in a specific MongoDB collection and print the results.
    
    Parameters:
    - collection: MongoDB collection to query
    - repo_name: Name of the repository
    - zero_field: Field to check for zero findings
    - description_fields: List of fields to display if findings are present
    """
    matching_document = collection.find_one({"repo_name": repo_name, zero_field: 0})
    if matching_document:
        print(f"No findings found in {collection.name} for repository: {repo_name}")
        print()
    else:
        findings = collection.find({"repo_name": repo_name})
        print(f"Findings in {collection.name}:")
        for doc in findings:
            for field in description_fields:
                print(f"{field}: {doc.get(field, 'N/A')}")
            print()
        print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <repo_url>")
        sys.exit(1)

    repo_url = sys.argv[1]
    repo_name = get_repo_name(repo_url)

    # Check Gitleaks findings
    gitleaks_collection = connect_to_mongo("gitleaks_reports")
    check_findings(
        gitleaks_collection,
        repo_name,
        "leaks",
        ["Description", "File", "StartLine", "EndLine"]
    )

    # Check Guarddog findings
    guarddog_collection = connect_to_mongo("guarddog_reports")
    check_findings(
        guarddog_collection,
        repo_name,
        "output_text",
        ["output_text", "rule_id"]
    )

    # Check Safety findings
    safety_collection = connect_to_mongo("safety_reports")
    check_findings(
        safety_collection,
        repo_name,
        "output",
        ["package_name"]
    )

    # Check Bearer findings
    bearer_collection = connect_to_mongo("bearer_reports")
    bearer_document = bearer_collection.find_one({"repository": repo_name})
    if bearer_document:
        bearer_findings = bearer_document.get("vulnerabilities", [])
        if bearer_findings:
            print("Vulnerabilities found by Bearer:")
            for idx, doc in enumerate(bearer_findings):
                print(f"Finding {idx + 1}:")
                print(f"Severity: {doc.get('severity', 'N/A')}")
                print(f"Description: {doc.get('description', 'No description available')}")
                print(f"File: {doc.get('file', 'N/A')}")
                print()
        else:
            print(f"No vulnerabilities found by Bearer for repository: {repo_name}")
    else:
        print(f"No Bearer report found for repository: {repo_name}")
