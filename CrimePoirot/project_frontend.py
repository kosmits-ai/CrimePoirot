import streamlit as st
import subprocess

def run_scripts_in_window(repo_url):
    """
    Runs scripts and captures the output.
    """
    # List of scripts to run
    scripts = ["main.py", "mongo_handler.py", "csv_handler.py"]
    output = []

    for idx, script in enumerate(scripts):
        output.append(f"Running {script}...\n")
        progress = st.progress(0)  # Add progress for each script
        
        try:
            if script == "main.py":
                result = subprocess.run(["python3", script, repo_url], text=True)
            else:
                result = subprocess.run(["python3", script, repo_url], capture_output=True, text=True)

            if result.returncode != 0:
                output.append(f"❌ {script} failed with exit code {result.returncode}.\nError:\n{result.stderr or 'No error message provided.'}\n")
            else:
                output.append(f"✅ {script} executed successfully.\nOutput:\n{result.stdout or 'No output.'}\n")
        except Exception as e:
            output.append(f"⚠️ An unexpected error occurred while running {script}: {e}\n")
        
        progress.progress((idx + 1) / len(scripts))  # Update progress

    output.append("🎉 All scripts executed successfully.")
    return output


def main():
    st.set_page_config(
        page_title="CrimePoirot",
        layout="centered",
        initial_sidebar_state="collapsed",
        page_icon="🔍"
    )

    # Header with a styled title
    st.markdown(
        """
        <style>
        .main-title {
            font-size: 2.5em;
            color: #2C3E50;
            text-align: center;
        }
        .sub-title {
            font-size: 1.2em;
            color: #7F8C8D;
            text-align: center;
        }
        .footer {
            text-align: center;
            color: #95A5A6;
            font-size: 0.9em;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
    st.markdown("<div class='main-title'>CrimePoirot</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Your GitHub Repository Analyzer</div>", unsafe_allow_html=True)
    st.write("---")

    # Tabs for navigation
    tabs = st.tabs(["🏠 Home", "🛠️ Run Scripts", "ℹ️ About"])
    
    # Home Tab
    with tabs[0]:
        st.subheader("Welcome to CrimePoirot!")
        st.markdown(
            """
            **CrimePoirot** helps you analyze GitHub repositories for vulnerabilities and calculates a trust score.
            
            ### 🔑 Features
            - Detects secrets using **GitLeaks**
            - Identifies supply chain risks with **Guarddog**
            - Checks dependencies for vulnerabilities via **Safety**
            - Scans codebases for sensitive data with **Bearer**
            
            ### 🚀 How to Use:
            1. Enter a GitHub repository URL.
            2. Run scripts to analyze the repository.
            3. View detailed results and trust scores.
            """
        )

    # Run Scripts Tab
    with tabs[1]:
        st.subheader("Analyze Your Repository")
        repo_url = st.text_input("🔗 Enter GitHub Repository URL", placeholder="https://github.com/username/repo.git")

        if st.button("Run Analysis"):
            if repo_url:
                with st.spinner("Running scripts... Please wait."):
                    output = run_scripts_in_window(repo_url)
                    st.success("Analysis Completed!")
                    st.text_area("📜 Script Output", value="\n".join(output), height=400)
            else:
                st.error("⚠️ Please enter a valid GitHub repository URL.")

    # About Tab
    with tabs[2]:
        st.subheader("About CrimePoirot")
        st.markdown(
            """
            ### 🔍 What is CrimePoirot?
            CrimePoirot is a tool designed for GitHub repository analysis. It integrates multiple open-source security tools to detect vulnerabilities and calculate a repository trust score.
            
            ### 📊 Tools Used:
            - **GitLeaks**: Detects secrets in codebases.
            - **Guarddog**: Identifies supply chain risks in Python dependencies.
            - **Safety**: Checks for known vulnerabilities in dependencies.
            - **Bearer**: Scans for sensitive data exposure.

            ### 🛠️ Made With:
            - **Python**
            - **Streamlit** for UI
            - **MongoDB** for data storage

            ### 🤖 Project source code:
            [CrimePoirot Repository](https://github.com/kosmits-ai/CrimePoirot)
            """
        )
    
    # Footer
    st.markdown(
        "<div class='footer'>© 2024 CrimePoirot - Built by Konstantinos Mitsionis</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()

