import streamlit as st
import subprocess
import re
from dotenv import load_dotenv
import os 

load_dotenv()


def run_scripts_in_window(repo_url):
    """
    Runs scripts and captures the output.
    """
    crimepoirot_dir = os.getenv("CRIMEPOIROT_DIR")
    # List of scripts to run
    os.chdir(crimepoirot_dir)
    scripts = ["main.py", "mongo_handler.py", "csv_handler.py"]
    output = [] # Add progress for each script
    progress = st.progress(0)
    for idx, script in enumerate(scripts):
        output.append(f"Running {script}...\n")
        result = subprocess.run(["python3", script, repo_url], text=True)
        try:
            if script == "csv_handler.py":
                result = subprocess.run(["python3", script, repo_url], capture_output=True, text=True)
            else:
                result = subprocess.run(["python3", script, repo_url], text=True)

            if result.returncode != 0:
                output.append(f"❌ {script} failed with exit code {result.returncode}.\nError:\n{result.stderr or 'No error message provided.'}\n")
            elif script == "main.py" or script == "mongo_handler.py":
                output.append(f"✅ {script} executed successfully.\n")
            else:
                output.append(f"✅ {script} executed successfully.\nOutput:{result.stdout}\n")
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

    # Header with Times New Roman font style
    st.markdown(
        """
        <style>
        body {
            font-family: 'Times New Roman', Times, serif;
        }

        .main-title {
            font-size: 2.5em;
            color: #3cd110;
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
    tabs = st.tabs(["🏠 Home", "🛠️ Run Scripts","📊 DB CrimePoirot", "ℹ️ About"])
    
    # Home Tab
    with tabs[0]:
        st.subheader("Welcome to CrimePoirot!")
        st.markdown(
            """
            ### 🔑 Features
            - Detects secrets using **GitLeaks**
            - Identifies supply chain risks with **Guarddog**
            - Checks dependencies for vulnerabilities via **Safety**
            - Scans codebases for sensitive data with **Bearer**
            
            ### 🚀 How to use:
            1. Enter a GitHub repository URL.
            2. Run scripts to analyze the repository.
            3. View detailed results and trust scores.
            
            ### ❓ How it works:
            1. You enter a github repository url.
            2. GitLeaks is running...
            3. Leaked credentials -if they exist- stored in MongoDB.
            4. Guarddog is running... **(requirements.txt is required in the repo you try to scan)**
            5. Malicious warnings -if they exist- are stored in MongoDB.
            6. Safety is running...
            7. Names of vulnerable packages -if they exist- are stored in MongoDB.
            8. Bearer is running...
            9. Count of _Critical, High, Medium, Low_ Vulnerabilities in the source code of the repository.
            10. A final document with counts of every feauture is stored in a seperate MongoDB collection.
            """  
        )

    # Run Scripts Tab
    with tabs[1]:
        st.subheader("Analyze Your Repository")
        repo_url = st.text_input("🔗 Enter GitHub Repository URL", placeholder="https://github.com/username/repo.git")

        if st.button("Run Analysis"):
            if repo_url:
                if re.match(r"https://github\.com/[\w-]+/[\w-]+(\.git)?", repo_url):
                    st.success("Valid GitHub repository URL!")
                    with st.spinner("Running scripts... Please wait."):
                        output = run_scripts_in_window(repo_url)
                        st.success("Analysis Completed!")
                        st.text_area("📜 Script Output", value="\n".join(output), height=400)
                else:
                    st.error("⚠️ Please enter a valid GitHub repository URL.")
            else:
                st.error("⚠️ Repository URL cannot be empty.")
    with tabs[2]:
        st.subheader("About CrimePoirot DataBase")
        st.markdown(
            """
            The main idea behind this project was building a tool that can check for various parameters which affect the security trust for a specific repository.
            After evaluating the findings of Gitleaks, GuardDog, Safety, Bearer for 100-150 random repositories, we calculate the mean values of each parameter.
            We do that in order to check how much a new repository which needs to be scanned will diverge from these mean values.
            According to this deviation, a trust score will be calculated.
            This score will help the owner/ developer to have a quick measure to check about how safe is the repository.\n\n
            """
        )
        workflow_path = st.secrets["WORKFLOW_IMAGE_PATH"]
        histograms_path = st.secrets["HISTOGRAMS_IMAGE_PATH"]
        st.markdown("##### Creation workflow of DataBase:")
        st.image(workflow_path,use_container_width= True)
        st.markdown("##### Histograms of DataBase Features:")
        st.image(histograms_path, use_container_width=True)


    # About Tab
    with tabs[3]:
        st.subheader("About CrimePoirot")
        st.markdown(
            """
            ### 🔍 What is CrimePoirot?
            CrimePoirot is a tool designed for GitHub repository analysis. It integrates multiple open-source security tools to detect vulnerabilities and calculate a repository trust score.
            
            ### ⚙️ Tools Used:
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


