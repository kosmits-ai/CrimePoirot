import subprocess
import os
import sys
import io



def get_repo_name(repo_url):
    """Extract the repository name from the URL."""
    return repo_url.split('/')[-1].replace('.git', '')

def clone_repo(repo_url):
    repo_name = get_repo_name(repo_url)
    # Set the base directory where you want to clone the repos
    base_dir = r'C:\Users\Panagiota\Desktop'  # Adjust this path as needed
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


def run_gitleaks(repo_path):
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
                    print(report_data)
            else:
                print(f"Report file not found: {report_path}")
        else:
            print(f"Gitleaks encountered an error with exit code {result.returncode}.")
            print(result.stderr)  # Print the stderr to see the error message
            
    except Exception as e:
        print("Error running Gitleaks:", e)
        sys.exit(1)


if __name__ == "__main__":
    
    if sys.platform.startswith('win'):
    # Set the default encoding to UTF-8 for Windows
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


    repo_url = input("Enter the repository URL: ")  # Get the repo URL from user input
    repo_path = clone_repo(repo_url)  # Store the path of the cloned repository or existing one
    
    run_gitleaks(repo_path)  
    
    
