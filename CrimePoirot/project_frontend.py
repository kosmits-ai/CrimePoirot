import streamlit as st
import subprocess
from threading import Thread

def run_scripts_in_window(repo_url):
    """
    Runs scripts and captures the output.
    """
    # List of scripts to run
    scripts = ["main.py", "mongo_handler.py", "csv_handler.py"]
    output = []

    for script in scripts:
        output.append(f"Running {script}...\n")
        
        try:
            if script == "main.py":
                # Pass through input/output streams for interactive behavior
                result = subprocess.run(["python3", script, repo_url], text=True)
            else:
                # Pass repo_url as a command-line argument and capture output
                result = subprocess.run(["python3", script, repo_url], capture_output=True, text=True)

            # Check for errors
            if result.returncode != 0:
                output.append(f"{script} failed with exit code {result.returncode}.\nError:\n{result.stderr or 'No error message provided.'}\n")
            else:
                output.append(f"{script} executed successfully.\nOutput:\n{result.stdout or 'No output.'}\n")

        except Exception as e:
            output.append(f"An unexpected error occurred while running {script}: {e}\n")

    output.append("All scripts executed successfully.")
    return output


def main():
    st.set_page_config(page_title="CrimePoirot", layout="centered")

    # Title and description
    st.title("CrimePoirot")
    st.markdown(
        """
        **Welcome to CrimePoirot!**
        
        This application detects vulnerabilities or malware in GitHub repositories 
        using various tools and calculates a trust score.
        """
    )

    # Navigation Menu
    menu = ["Home", "Run Scripts", "Info"]
    choice = st.sidebar.selectbox("Menu", menu)

    # Home Section
    if choice == "Home":
        st.subheader("Home")
        st.markdown(
            """
            ### Instructions
            1. Enter a GitHub repository URL.
            2. Run scripts to analyze the repository.
            3. Check the output for results.
            """
        )

    # Run Scripts Section
    elif choice == "Run Scripts":
        st.subheader("Run Scripts")
        repo_url = st.text_input("Enter GitHub Repository URL", placeholder="https://github.com/username/repo.git")

        if st.button("Run"):
            if repo_url:
                with st.spinner("Running scripts..."):
                    output = run_scripts_in_window(repo_url)
                    # Display the output as a joined string from the list
                    st.text_area("Script Output", value="\n".join(output), height=400)
            else:
                st.error("Please enter a valid GitHub repository URL.")

    # Info Section
    elif choice == "Info":
        st.subheader("Info")
        st.markdown(
            """
            ## About CrimePoirot
            
            This tool uses the following open-source projects:
            1. **GitLeaks**: Detects secrets like passwords, API keys, and tokens.
            2. **Guarddog**: Identifies supply chain risks in Python dependencies.
            3. **Safety**: Checks dependencies for known vulnerabilities.
            4. **Bearer**: Scans codebases for sensitive data exposure.

            The findings are combined to calculate a **repository trust score** based on vulnerability metrics.
            
            GitHub repository of the project: [CrimePoirot](https://github.com/kosmits-ai/CrimePoirot)
            """
        )


if __name__ == "__main__":
    main()

