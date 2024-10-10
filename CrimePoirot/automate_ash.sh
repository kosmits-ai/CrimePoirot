#!/bin/bash

# Open Windows Terminal
## Enable WSL connection
### Do cd /mnt/c/Users/Panagiota/Desktop/CrimePoirot/CrimePoirot
#### Make the file executable chmod +x automate_ash.sh
##### Run ./automate_ash.sh


REPO_DIR="${HOME}/Documents/repos/reference"
REPO_NAME="automated-security-helper"
OUTPUT_DIR="${REPO_DIR}/${REPO_NAME}/output_results"        #I need to take the name of the repo to be scanned as input 
SCAN_REPO_DIR="${HOME}/Documents/RepoForTest/vulpy"



setup_environment(){
    echo "Setting up the environment"

    sudo apt-get update
    
    sudo npm install -g nmp pnpm yarn
}

clone_setup_ash(){
    echo "Cloning the repository and setting up ASH..."

    # Create repo directory if it doesn't exist
    mkdir -p "${REPO_DIR}"

    # Clone the automated-security-helper repo
    if [ ! -d "${REPO_DIR}/${REPO_NAME}" ]; then
        git clone https://github.com/awslabs/automated-security-helper.git "${REPO_DIR}/${REPO_NAME}"
    fi

    # Go to the utils directory and install necessary npm packages
    cd "${REPO_DIR}/${REPO_NAME}/utils/cdk-nag-scan"
    sudo npm install --quiet
}

run_ash_scan() {
    echo "Running ASH scan on ${SCAN_REPO_DIR}..."

    # Run the scan using the ASH tool
    cd "${REPO_DIR}/${REPO_NAME}"
    ./ash --source-dir "${SCAN_REPO_DIR}" --output-dir "${OUTPUT_DIR}"

    echo "Scan completed. The report can be found in ${OUTPUT_DIR}/aggregated_results.txt"
}

display_report() {
    if [ -f "${OUTPUT_DIR}/aggregated_results.txt" ]; then
        echo "Aggregated Results:"
        cat "${OUTPUT_DIR}/aggregated_results.txt"
    else
        echo "No report found."
    fi
}

main() {
    setup_environment
    clone_and_setup_repo
    run_ash_scan
    display_report
}

main
