#!/bin/bash

#Enable WSL connection

# Load environment variables from .env file
set -o allexport  # Enable automatic export of variables
source ../.env 
set +o allexport  # Disable automatic export of variables

# Define the necessary directories from the .env file
OUTPUT_DIR="${OUTPUT_DIR}"   # Output directory for scan results

read -p 'Enter the directory of the repository to be scanned: ' SCAN_REPO_DIR


setup_environment() {
    echo "Setting up the environment..."
    
    # Update package list and install required npm packages
    sudo apt-get update
    sudo npm install -g npm pnpm yarn  # Corrected 'nmp' to 'npm'
}
clone_and_setup_ash() {
    echo "Cloning the repository and setting up ASH..."

    # Create repo directory if it doesn't exist
    mkdir -p "${REPO_DIR}"

    # Clone the automated-security-helper repo if it doesn't exist
    if [ ! -d "${REPO_DIR}/${REPO_NAME}" ]; then
        git clone https://github.com/awslabs/automated-security-helper.git "${REPO_DIR}/${REPO_NAME}"
    else
        echo "Repository already exists. Skipping clone."
    fi

    # Go to the utils directory and install necessary npm packages
    cd "${REPO_DIR}/${REPO_NAME}/utils/cdk-nag-scan" || exit  # Ensure cd succeeds
    sudo npm install --quiet
}
run_ash_scan() {
    echo "Running ASH scan on ${SCAN_REPO_DIR}..."

    # Check if the scan repository directory exists
    if [ ! -d "${SCAN_REPO_DIR}" ]; then
        echo "Error: Scan repository directory ${SCAN_REPO_DIR} does not exist."
        exit 1  # Exit if the directory does not exist
    fi

    # Run the scan using the ASH tool
    cd "${REPO_DIR}/${REPO_NAME}" || exit  # Ensure cd succeeds
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
    clone_and_setup_ash  # Call the corrected function
    run_ash_scan
    display_report
}
main
