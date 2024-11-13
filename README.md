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

## **Run the Scripts:**
1. Run four tools in serial architecture: `python main.py` 
2. Save the results in CSV file: `python mongo_handler.py`

## **How it works:**
1. You enter a github repository url.
2. GitLeaks is running...
3. Leaked credentials -if they exist- stored in MongoDB.
4. Guarddog is running... **(requirements.txt is required in the repo you try to scan)**
5. Malicious warnings -if they exist- are stored in MongoDB.
6. Safety is running...
7. Names of vulnerable packages -if they exist- are stored in MongoDB.
8. Bearer is running...
9. Count of _Critical, High, Medium, Low_ Vulnerabilities in the source code of the repository.

**PS.** If everything is clear according to a tool, we insert output documents with zero-empty values in MongoDB.

## **Main idea behind this project**
The main idea behind this project was building a tool that can check for various parameters which affect the security trust for a specific repository. After evaluating the findings of **Gitleaks, GuardDog, Safety, Bearer** for _100-150_ random repositories, we calculate the mean values of each parameter. We do that in order to check how much a new repository which needs to be scanned will diverge from these mean values. According to this δeviation, a trust score will be calculated. This score will help the owner/ developer to have a quick measure to check about how safe is the repository.
