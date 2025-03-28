import pandas as pd
import matplotlib.pyplot as plt

# Function to convert data size to bytes
def convert_to_bytes(size_str):
    if 'B' in size_str:
        # Handle 'B' suffix (Bytes)
        if 'KB' in size_str:
            # Handle 'KB' (Kilobytes)
            return int(size_str.replace('KB', '')) * 1024
        elif 'MB' in size_str:
            # Handle 'MB' (Megabytes)
            return int(size_str.replace('MB', '')) * 1024 * 1024
        return int(size_str.replace('B', ''))
    return 0  # If no recognized size, return 0

# Load the CSV file with entropy results for 3DES CBC
data = pd.read_csv('des3_cbc_entropy_results.csv')

# Display the first few rows of the data to ensure it's loaded correctly
print(data.head())

# Convert the 'Data Size (Bytes)' to numeric values for proper plotting
data['Data Size (Bytes)'] = data['Data Size (Bytes)'].apply(convert_to_bytes)

# Plot the entropy values
plt.figure(figsize=(10, 6))
plt.plot(data['Data Size (Bytes)'], data['Average Entropy (bits/byte)'], marker='o', linestyle='-', color='b')

# Customize the plot
plt.title('Average Entropy of 3DES-CBC Encryption by Data Size')
plt.xlabel('Data Size (Bytes)')
plt.ylabel('Average Entropy (bits/byte)')
plt.grid(True)
plt.xscale('log')  # Log scale for better visibility of larger data sizes

# Set the x-ticks labels to display sizes like '8B', '16B', '1KB', etc.
plt.xticks([8, 16, 50, 200, 500, 1024, 100*1024, 250*1024, 500*1024, 750*1024, 1024*1024], 
           ['8B', '16B', '50B', '200B', '500B', '1KB', '100KB', '250KB', '500KB', '750KB', '1MB'])

# Rotate the x-axis labels for better visibility
plt.xticks(rotation=45, ha='right')

# Save the plot as a PNG image
plt.tight_layout()
plt.savefig('des3_cbc_entropy_plot.png')

# Show the plot
plt.show()
