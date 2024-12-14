import pandas as pd

# Define the data in a dictionary format
data = {
    "ID": [1, 2, 3, 4],
    "Name": ["John Doe", "Jane Smith", "Alice Johnson", "Bob Brown"],
    "Age": [29, 34, 22, 45],
    "Country": ["USA", "Canada", "UK", "Australia"]
}

# Create a DataFrame
df = pd.DataFrame(data)

# Export the DataFrame to an Excel file using pandas (openpyxl is used as the engine automatically)
df.to_excel("output.xlsx", index=False, sheet_name="Sheet1")

print("Excel file 'output.xlsx' has been created successfully.")
