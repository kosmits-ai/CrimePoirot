import subprocess
import os
import sys
import io
import json
from pymongo import MongoClient

def connect_to_mongo(repo_name):
    try:
        mongo_url = "mongodb+srv://kmitsionis:iD0thfzj2mZWq78q@cluster0.dqqb4yn.mongodb.net/"
        client = MongoClient(mongo_url)
        db = client["gitleaks_reports"]
        
        # Collection names must be lowercase and can only contain letters, numbers, underscores, and dollar signs
        collection_name = repo_name.lower().replace(' ', '_')  # Format repo name for collection
        collection = db[collection_name]  # Create a collection with the repo name
        return collection
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}")
        sys.exit(1)  

def store_mongo(report_data, collection, repo_name):
    try:
        # Load the JSON data from the Gitleaks report
        report_json = json.loads(report_data)

        # Check if the JSON report is a list (array) or a dictionary (object)
        if isinstance(report_json, list):
            # If it's a list, add the repo_name to each item and insert them individually
            for item in report_json:
                if isinstance(item, dict):  # Ensure each element is a dictionary
                    item["repo_name"] = repo_name
                    collection.insert_one(item)  # Insert each item individually
        elif isinstance(report_json, dict):
            # If it's a single dictionary, just add the repo_name and insert it
            report_json["repo_name"] = repo_name
            collection.insert_one(report_json)

        print(f"Report successfully stored in MongoDB for {repo_name}.")
    except Exception as e:
        print(f"Error storing report in MongoDB: {e}")


def get_repo_name(repo_url):
    """Extract the repository name from the URL."""
    return repo_url.split('/')[-1].replace('.git', '')

def clone_repo(repo_url):
    repo_name = get_repo_name(repo_url)
    # Set the base directory where you want to clone the repos
    base_dir = r'C:\Users\Panagiota\Desktop\RepoForTest'  # Adjust this path as needed
    clone_dir = os.path.join(base_dir, repo_name)  # Set the clone directory path

    # Check if the clone directory already exists
    if os.path.exists(clone_dir):
        print(f"The directory '{clone_dir}' already exists. Skipping cloning.")
        return clone_dir  # Return the path of the existing repository

    try:
        print(f"Cloning the repository from {repo_url} to {clone_dir}...")
        subprocess.run(['git', 'clone', repo_url, clone_dir], check=True)
        print("Clone completed successfully.")
        return clone_dir  # Return the path of the cloned repository
    except subprocess.CalledProcessError as e:
        print("Error cloning the repository:", e)
        sys.exit(1)


def run_gitleaks(repo_path,collection,repo_url):
    gitleaks_path = r'C:\Users\Panagiota\Desktop\gitleaks\gitleaks\gitleaks.exe'  # Full path to gitleaks.exe
    report_path = os.path.join(repo_path, 'gitleaks_report.json')  # Set report path

    try:
        print(f"Running Gitleaks on {repo_path}...")
        result = subprocess.run(
            [gitleaks_path, 'git', repo_path, '--report-format', 'json', '--report-path', report_path],
            check=False,  # Set check to False to allow capturing exit codes
            capture_output=True,
            text=True
        )
        
        # Check the exit code
        if result.returncode == 0:
            print("Gitleaks completed successfully.")
        elif result.returncode == 1:
            print("Gitleaks found leaks.")
            # Check if the report file exists before trying to open it
            if os.path.exists(report_path):
                with open(report_path) as report_file:
                    report_data = report_file.read()
                    repo_name = get_repo_name(repo_url)  # Extract repo name for context
                    store_mongo(report_data,collection, repo_name)  # Store in MongoDB
            else:
                print(f"Report file not found: {report_path}")
        else:
            print(f"Gitleaks encountered an error with exit code {result.returncode}.")
            print(result.stderr)

    except Exception as e:
        print("Error running Gitleaks:", e)
        sys.exit(1)

def run_guarddog(clone_dir):
    if not os.path.exists(clone_dir):
        print(f"Error: {clone_dir} does not exist.")
        return

    try:

        requirements_path = os.path.join(clone_dir, 'requirements.txt')
        
        output_file = os.path.join(clone_dir, 'guarddog.sarif')
        
        command = [
            'guarddog', 'pypi', 'verify', requirements_path,
            '--output-format', 'sarif', 
            '--exclude-rules', 'repository_integrity_mismatch'
        ]

        print(f"Running GuardDog to scan {requirements_path}...")

        
        with open(output_file, 'w') as outfile:
            result = subprocess.run(command, stdout=outfile, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            print("GuardDog completed successfully. Report saved as guarddog.sarif.")

        else:
            print(f"GuardDog encountered an error (exit code: {result.returncode}).")
            print(result.stderr)  

    except Exception as e:
        print(f"Error running GuardDog: {e}")


if __name__ == "__main__":
    # Get repo URL from user input
    repo_url = input("Enter the repository URL: ")
    
    # Connect to MongoDB Atlas and get the collection
    repo_name = get_repo_name(repo_url)
    repo_path = clone_repo(repo_url)
    
    
    collection = connect_to_mongo(repo_name)  # This stores the collection returned from connect_to_mongo

  

    # Run Gitleaks and pass the collection object to it
    run_gitleaks(repo_path, collection,repo_url)  # Collection is passed here to run_gitleak
    
    run_guarddog(repo_path)
