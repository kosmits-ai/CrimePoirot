import subprocess
import os
import sys
import json
import re
from collections import defaultdict
from pymongo import MongoClient
from dotenv import load_dotenv

############## After enabling venv you have to do $env:PYTHONUTF8="1" in order to make guarddog and safety run properly. #######################


# Load environment variables from the .env file
load_dotenv()

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
    # Use BASE_DIR from the .env file
    base_dir = os.getenv("BASE_DIR")  # Get base directory from environment variable
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

def get_current_commit(repo_path):
    """Returns the current commit hash of the repo at the given path."""
    try:
        # Navigate to the repository directory
        result = subprocess.run(
            ['git', '-C', repo_path, 'rev-parse', 'HEAD'], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            # The current commit hash
            current_commit = result.stdout.strip()
            return current_commit
        else:
            print(f"Error getting the current commit: {result.stderr}")
            return None
    except Exception as e:
        print(f"Error while getting current commit: {e}")
        return None

def analyze_gitleaks_report(report_data, current_commit):
    leaks = json.loads(report_data)

    total_leaks = len(leaks)
    print(f"Total leaks found: {total_leaks}")

    leaks_by_commit = defaultdict(int)

    for leak in leaks:
        commit = leak["Commit"]
        leaks_by_commit[commit] += 1
        if current_commit == commit:
            print(f"Number of leaks in the current commit ({current_commit}): {leaks_by_commit[current_commit]}")

    # Output the analysis summary
    for commit, count in leaks_by_commit.items():
        print(f"Commit: {commit} - Total Leaks: {count}")

def analyze_guarddog(report_data):
    output_data = report_data.get('runs', [])[0].get('results', [])
    total_results = len(output_data)
    print(f"Total warnings of maliciousness found: {total_results}")

def run_gitleaks(repo_path, collection, repo_url, current_commit):
    gitleaks_path = os.getenv("GITLEAKS_PATH")  # Get path to gitleaks executable from environment variable
    print(f"Gitleaks path: {gitleaks_path}")  # Print the path for debugging
    report_path = os.path.join(repo_path, 'gitleaks_report.json')  # Set report path

    try:
        print(f"Running Gitleaks on {repo_path}...")

        # Mark the directory as safe for Git (prevents dubious ownership errors)
        result_git_safe = subprocess.run(
            ['git', 'config', '--global', '--add', 'safe.directory', repo_path],
            check=False,
            capture_output=True,
            text=True
        )
        if result_git_safe.returncode != 0:
            print(f"Error marking directory as safe: {result_git_safe.stderr}")
            sys.exit(1)

        # Verify that the Gitleaks path exists
        if not os.path.isfile(gitleaks_path):
            print(f"Error: Gitleaks executable not found at {gitleaks_path}")
            sys.exit(1)

        # Debug the command being run
        print(f"Command to run: [{gitleaks_path}, 'detect', '--source', {repo_path}, '--report-format', 'json', '--report-path', {report_path}]")

        # Run Gitleaks with the "detect" command
        result = subprocess.run(
            [gitleaks_path, 'detect', '--source', repo_path, '--report-format', 'json', '--report-path', report_path],
            check=False,  # Allow capturing exit codes
            capture_output=True,
            text=True
        )

        # Output stdout and stderr for debugging
        print("Gitleaks stdout:", result.stdout)
        print("Gitleaks stderr:", result.stderr)

        # Check the exit code
        if result.returncode == 0:
            print("Gitleaks completed successfully.")
        elif result.returncode == 1:
            print("Gitleaks found leaks.")
            if os.path.exists(report_path):
                with open(report_path) as report_file:
                    report_data = report_file.read()
                    repo_name = get_repo_name(repo_url)  # Extract repo name for context
                    analyze_gitleaks_report(report_data, current_commit)
            else:
                print(f"Report file not found: {report_path}")
        else:
            print(f"Gitleaks encountered an error with exit code {result.returncode}.")
            print(result.stderr)

    except Exception as e:
        print("Error running Gitleaks:", e)
        sys.exit(1)

def run_safety(repo_path, collection, repo_url): 
    try:
        os.chdir(repo_path)
        print(f"Running Safety on {repo_path}...")

        # Run the safety scan command
        result = subprocess.run(['safety', 'scan'], capture_output=True, text=True)

        repo_name = get_repo_name(repo_url)

        # Print the raw output for debugging
        print("Safety scan output:\n", result.stdout)

        # Split the output into lines
        lines = result.stdout.splitlines()
        vulnerabilities = []
        package_name = None

        for line in lines:
            # Match the package line with vulnerabilities count (handles both singular/plural)
            package_match = re.match(r"^(.*?)==(\d+\.\d+\.\d+)\s+\[(\d+) vulnerabilit(?:y|ies) found\]$", line.strip())
            if package_match:
                # Found a new package, set the package name
                package_name = package_match.group(1)
                print(f"Package found: {package_name}")
                continue

            # Match vulnerability details with or without CVE
            vuln_match = re.match(r"^\s*-> Vuln ID (\d+): (?:CVE-(\d+)-(\d+), )?CVSS Severity (.*)", line.strip())
            if vuln_match and package_name:
                vuln_id = vuln_match.group(1)
                severity = vuln_match.group(4)  # Using group 4 for severity
                vulnerabilities.append({
                    "repo_name": repo_name,
                    "package_name": package_name,
                    "vuln_id": vuln_id,
                    "severity": severity
                })
                print(f"Vulnerability added: {vuln_id} - Severity: {severity}")
                print()

        # Insert vulnerabilities into the database if found
        if vulnerabilities:
            collection.insert_many(vulnerabilities)
            print(f"Inserted {len(vulnerabilities)} vulnerabilities for repo {repo_name} into the database.")
        else:
            print("No vulnerabilities found.")

    except FileNotFoundError:
        print(f"Error: The directory {repo_path} does not exist.")
    except subprocess.CalledProcessError as e:
        print(f"Error running safety scan: {e.stderr}")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

def run_guarddog(clone_dir, collection, repo_url):
    repo_name = get_repo_name(repo_url)
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
        print()

        with open(output_file, 'w') as outfile:
            result = subprocess.run(command, stdout=outfile, stderr=subprocess.PIPE, text=True)
        
        with open(output_file, 'r') as sarif_file:
            sarif_data = json.load(sarif_file)
        
        output_data = sarif_data.get('runs', [])[0].get('results', [])
        
        for result in output_data:
            rule_id = result.get('ruleId', 'N/A')
            output_text = result.get('message', {}).get('text', 'N/A') 
            document = {
                "repo_name": repo_name,
                "rule_id": rule_id,
                "output_text": output_text
            }
            collection.insert_one(document)

        analyze_guarddog(sarif_data)
        print()
        print("Guarddog completed successfully.")
    
    except Exception as e:
        print("Error running Guarddog:", e)
        sys.exit(1)

def query_severity(collection, repo_name):
    num_high_severity = 0
    high_severity_docs = collection.find({"severity": "HIGH", "repo_name": repo_name})
    for doc in high_severity_docs:
        num_high_severity += 1
    print(num_high_severity)

def leaks_current(collection, current_commit):
    num_current_leaks = 0
    leaks = collection.find({"Commit": current_commit})
    for leak in leaks:  
        num_current_leaks += 1
    print(f"Leaks passed in current commit: {num_current_leaks}")




# Define directories from environment variables
REPO_DIR = os.getenv("REPO_DIR")
REPO_NAME = "automated-security-helper"
OUTPUT_DIR = os.getenv("OUTPUT_DIR")


def setup_environment():
    """Set up the necessary environment and dependencies."""
    print("Setting up the environment...")
    try:
        subprocess.run(['sudo', 'apt-get', 'update'], check=True)
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'npm'], check=True)
        subprocess.run(['sudo', 'npm', 'install', '-g', 'pnpm', 'yarn'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error during environment setup: {e}")
        exit(1)


def clone_and_setup_ash():
    """Clone ASH repo and set up required dependencies."""
    print("Cloning ASH repository and setting up dependencies...")

    # Ensure the base repository directory exists
    os.makedirs(REPO_DIR, exist_ok=True)
    ash_repo_path = os.path.join(REPO_DIR, REPO_NAME)

    # Clone repository if it doesn't exist
    if not os.path.isdir(ash_repo_path):
        try:
            subprocess.run(
                ['git', 'clone', 'https://github.com/awslabs/automated-security-helper.git', ash_repo_path],
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Error cloning repository: {e}")
            exit(1)
    else:
        print("ASH repository already exists. Skipping clone.")

    # Install npm dependencies in cdk-nag-scan directory
    try:
        cdk_scan_dir = os.path.join(ash_repo_path, 'utils', 'cdk-nag-scan')
        subprocess.run(['sudo', 'npm', 'install', '--quiet'], cwd=cdk_scan_dir, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error setting up dependencies: {e}")
        exit(1)


def run_ash_scan(repo_path):
    """Run ASH scan on the specified repository directory."""
    print(f"Running ASH scan on {repo_path}...")

    # Check if the scan repository directory exists
    if not os.path.isdir(repo_path):
        print(f"Error: Specified directory {repo_path} does not exist.")
        exit(1)

    ash_repo_path = os.path.join(REPO_DIR, REPO_NAME)
    output_file = os.path.join(OUTPUT_DIR, 'aggregated_results.txt')

    try:
        subprocess.run(
            ['./ash', '--source-dir', repo_path, '--output-dir', OUTPUT_DIR],
            cwd=ash_repo_path,
            check=True
        )
        print(f"Scan completed. The report is available at {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error running ASH scan: {e}")
        exit(1)


def display_report():
    """Display the aggregated results after the scan."""
    report_file = os.path.join(OUTPUT_DIR, 'aggregated_results.txt')
    if os.path.isfile(report_file):
        print("Aggregated Results:")
        with open(report_file, 'r') as f:
            print(f.read())
    else:
        print("No report found.")


def main(repo_path):
    """Main function to orchestrate the setup, scanning, and reporting."""
    setup_environment()
    clone_and_setup_ash()
    run_ash_scan(repo_path)
    display_report()

if __name__ == "__main__":
    os.environ["PYTHONUTF8"] = "1"

    # Get repo URL from user input
    repo_url = input("Enter the repository URL: ")
    
    # Connect to MongoDB Atlas and get the collection
    repo_name = get_repo_name(repo_url)
    repo_path = clone_repo(repo_url)
    
    current_commit = get_current_commit(repo_path)
    if current_commit:
        print(f"Current commit hash: {current_commit}")
        print()
    else:
        print("Failed to retrieve current commit.")
        print()

    collection = connect_to_mongo('gitleaks_reports')  # This stores the collection returned from connect_to_mongo
    #Run Gitleaks and pass the collection object to it
    run_gitleaks(repo_path, collection, repo_url, current_commit)  # Collection is passed here to run_gitleaks
    leaks_current(collection, current_commit)
    #print()
    #print()

    collection = connect_to_mongo('guarddog_reports')
    run_guarddog(repo_path, collection, repo_url)
    
    collection = connect_to_mongo('safety_reports')
    run_safety(repo_path, collection, repo_url)
    query_severity(collection, repo_name)

    main(repo_path)
