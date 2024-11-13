# CrimePoirot
## **Introduction**
My work for my diploma thesis _Detecting Vulnerabilities/Malware with Python_ . 
I used four open source projects from Github:
1. **GitLeaks** : Secret Detection like passwords, API keys, and tokens in git repos, files
2. **GuardDog** : Identification of malicious PyPI and npm packages or Go modules
3. **Safety** : Python dependency vulnerability scanner
4. **Bearer** : Static application security testing (SAST) tool that scans the source code and analyzes the data flows to discover, filter and prioritize security and privacy risks.

## **How To Use:**
What steps to follow in order to use _CrimePoirot_:
1. Enable **WSL** in terminal.
2. In root directory: `git clone https://github.com/kosmits-ai/CrimePoirot.git`
3. In root directory: `git clone https://github.com/gitleaks/gitleaks`
4. If you have Go installed:
- `cd gitleaks`
- `make build`
5. Create venv and enable it in root directory:
  - `python3 -m venv myenv`
  - `enable source myenv/bin/activate`
6. Navigate to _CrimePoirot_ and install the required staff:
  - `cd CrimePoirot`
  - `pip install -r requirements.txt`
7.  Authentication for **Safety** :
  - `safety auth`
8. Install **Bearer** package:
  - ```
    sudo apt-get install apt-transport-https
    echo "deb [trusted=yes] https://apt.fury.io/bearer/ /" | sudo tee -a /etc/apt/sources.list.d/fury.list
    sudo apt-get update
    sudo apt-get install bearer
9. Create **.env** in CrimePoirot folder:
  - Define **MONGO_URL**
  - Define **BASE_DIR** where the repos will be cloned
  - Define **GITLEAKS_PATH** where the build of Gitleaks is located to.

## **Run the Scripts**
1. Run four tools in serial architecture: `python main.py` 
2. Save the results in CSV file: `python mongo_handler.py`

