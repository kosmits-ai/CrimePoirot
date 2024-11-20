import pandas as pd
import numpy as np

# Load your dataset (assuming 'df' is already cleaned and contains only numerical features)
csv_file = '/home/kosmits/CrimePoirot/report.csv'  # Set the path to your actual file
df = pd.read_csv(csv_file)

# Drop non-numeric columns (like 'Repo_Name' or any other non-numeric columns)
df = df.drop(columns=['Repo_Name'], errors='ignore')  # Ignore errors in case 'Repo_Name' is not present
# Drop a specific column by name
df = df.drop(columns=['Current Commit Leaks'])

# Ensure the DataFrame is now numeric
df = df.apply(pd.to_numeric, errors='coerce')
df_filled = df.fillna(0)


'''
# Variance based
variances = df.var()
feature_weights = variances / variances.sum()
print("Feature Weights (Variance-Based):")
print(feature_weights)
'''

'''
# Z-Score based
z_scores = (df - df.mean()) / (df.std() + 1e-8)  # Add small constant to avoid division by zero
z_variability = z_scores.abs().mean()
feature_weights = z_variability / z_variability.sum()
print("Z-Score-Based Feature Weights:\n", feature_weights)
'''

'''
cv = df.std() / (df.mean() + 1e-8)  # Add small constant to avoid division by zero
feature_weights = cv / cv.sum()
print("Coefficient of Variation-Based Feature Weights:\n", feature_weights)
'''
'''
ranges = df.max() - df.min()
feature_weights = ranges / ranges.sum()
print("Range-Based Feature Weights:\n", feature_weights)
'''
'''
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

# Assuming 'df_filled' is your preprocessed DataFrame
# Perform PCA with all components (matching the number of features)
pca = PCA(n_components=df_filled.shape[1])  # df_filled.shape[1] gives the number of features
pca.fit(df_filled)

# Get feature importance (loadings) for each principal component
loadings = pd.DataFrame(pca.components_.T, index=df_filled.columns, columns=[f'PC{i+1}' for i in range(pca.n_components_)])

# Explained variance ratio for each principal component
explained_variance = pca.explained_variance_ratio_

# Display loadings and explained variance
print("Feature Contributions (Loadings):\n", loadings)
print("\nExplained Variance Ratios:\n", explained_variance)

# Visualize the transformed data (first two principal components)
pca_result = pca.transform(df_filled)  # Transform the data
df_pca = pd.DataFrame(pca_result, columns=[f'PC{i+1}' for i in range(pca.n_components_)])

plt.figure(figsize=(8, 6))
plt.scatter(df_pca['PC1'], df_pca['PC2'], alpha=0.7, c='blue', edgecolors='k', s=100)
plt.title('PCA: First Two Principal Components')
plt.xlabel('PC1')
plt.ylabel('PC2')
plt.grid(True)
plt.show()

# Print explained variance ratio for the first two components and total variance explained
print(f'Explained Variance Ratio for PC1 and PC2: {explained_variance[:2]}')
print(f'Total Explained Variance: {explained_variance.sum()}')

# Calculate feature weights based on PCA loadings
# Sum of the absolute loadings across all components for each feature
abs_loadings_sum = loadings.abs().sum(axis=1)

# Normalize the loadings to get the relative weights for each feature
feature_weights = abs_loadings_sum / abs_loadings_sum.sum()

# Print the feature weights
print("\nFeature Weights based on PCA Loadings:")
print(feature_weights)
'''
