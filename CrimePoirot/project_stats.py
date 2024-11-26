from dotenv import load_dotenv
import os 
import pandas as pd

def connect_to_mongo(collection_name):
    try:
        mongo_url = os.getenv("MONGO_URL")  # Get MongoDB URL from environment variable
        client = MongoClient(mongo_url)
        db = client["DiplomaThesis"]
        collection = db[collection_name]  
        return collection
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}")
        sys.exit(1) 

load_dotenv()
csv_path = os.getenv("CSV_PATH")

data = pd.read_csv(csv_path)

data['Low Vulns'] = pd.to_numeric(data['Low Vulns'], errors='coerce').fillna(0).astype(int)

# Replace "No requirements.txt" with 0
data['Guarddog findings'] = data['Guarddog findings'].replace('No requirements.txt', 0)

# Convert the column to numeric
data['Guarddog findings'] = pd.to_numeric(data['Guarddog findings'], errors='coerce')
columns_to_analyze = ['Total Repo Leaks', 'Guarddog findings', 'Safety findings', 'Critical Vulns', 'High Vulns', 'Medium Vulns', 'Low Vulns']

for i, col in enumerate(columns_to_analyze):
    feature_data = data[col]

    # Calculate statistics
    mean_val = feature_data.mean()
    median_val = feature_data.median()
    std_val = feature_data.std()
    q1_val = feature_data.quantile(0.25)
    q3_val = feature_data.quantile(0.75)
    min_val = feature_data.min()
    max_val = feature_data.max()

    # Print the results
    print(f"Statistics for {col}:")
    print(f"  Mean: {mean_val}")
    print(f"  Median: {median_val}")
    print(f"  Standard Deviation: {std_val}")
    print(f"  1st Quartile (Q1 - 58.57%): {q1_val}")
    print(f"  3rd Quartile (Q3 - 75%): {q3_val}")
    print(f"  Min: {min_val}")
    print(f"  Max: {max_val}")
    print("---------------------------------------------------------------------------------")
