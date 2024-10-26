import requests
import random

# GitHub API URL for repository search
api_url = "https://api.github.com/search/repositories"
query = "stars:<100 language:Python size:0..10000"  # Python repositories up to 10 MB in size
headers = {
    "Accept": "application/vnd.github.v3+json"
}

# Parameters for the API request
params = {
    "q": query,
    "sort": "stars",  # Sort by popularity
    "order": "desc",
    "per_page": 50,   # Fetch 50 repositories per page
    "page": 1         # Start from the first page
}

# Collect repositories in a list
all_repos = []

# Loop to fetch multiple pages until we have at least 100 repositories
while len(all_repos) < 100:
    response = requests.get(api_url, headers=headers, params=params)
    response_data = response.json()
    
    # Check if the request was successful
    if response.status_code == 200 and "items" in response_data:
        repos = response_data["items"]
        all_repos.extend(repos)
        
        # If there are fewer results than requested, we may have hit the end of the results
        if len(repos) < params["per_page"]:
            break
        
        # Move to the next page
        params["page"] += 1
    else:
        print("Failed to retrieve repositories:", response_data.get("message", "Unknown error"))
        break

# Randomly select 100 unique repositories if more than 100 were collected
if len(all_repos) > 100:
    random_repos = random.sample(all_repos, 100)
else:
    random_repos = all_repos

# Extract URLs of the selected repositories
random_urls = [repo["html_url"] for repo in random_repos]

# Print the URLs of the random repositories
for url in random_urls:
    print(url)
