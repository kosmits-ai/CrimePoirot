import subprocess

# List of scripts to run
scripts = ["main.py", "mongo_handler.py", "csv_handler.py"]

for script in scripts:
    print(f"Running {script}...")
    
    if script == "main.py":
        # Pass input/output streams to allow interactive behavior
        result = subprocess.run(["python3", script], text=True)
    else:
        # Standard behavior for non-interactive scripts
        result = subprocess.run(["python3", script], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"{script} failed! Exiting.\nError:\n{result.stderr}")
        exit(1)

print("All scripts executed successfully.")
