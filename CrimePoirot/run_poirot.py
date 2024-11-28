import subprocess
import sys

# Define the repository URL
repo_url = input("Enter the repository URL: ")

# List of scripts to run
scripts = ["main.py", "mongo_handler.py", "csv_handler.py"]

for script in scripts:
    print(f"Running {script}...")
    
    try:
        if script == "main.py":
            # Pass through input/output streams for interactive behavior
            result = subprocess.run(["python3", script, repo_url], text=True)
        else:
            # Pass repo_url as a command-line argument
            result = subprocess.run(["python3", script, repo_url], capture_output=True, text=True)

        # Check for errors
        if result.returncode != 0:
            print(f"{script} failed with exit code {result.returncode}.\nError:\n{result.stderr or 'No error message provided.'}")
            exit(1)
        else:
            print(f"{script} executed successfully.\nOutput:\n{result.stdout or 'No output.\n'}")

    except Exception as e:
        print(f"An unexpected error occurred while running {script}: {e}")
        exit(1)

print("All scripts executed successfully.")


