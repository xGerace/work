import os
from tenable.io import TenableIO
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up API keys from environment variables
access_key = os.getenv("TENABLE_ACCESS_KEY")
secret_key = os.getenv("TENABLE_SECRET_KEY")

# Initialize TenableIO with your API keys
tio = TenableIO(access_key, secret_key)
print("TenableIO session initialized.")

# Specify the VPR score ranges
vpr_ranges = [
    {'name': 'Critical', 'gte': 9.0, 'lte': 10.0},
    {'name': 'High', 'gte': 7.0, 'lt': 9.0},
    {'name': 'Medium', 'gte': 4.0, 'lt': 7.0},
    {'name': 'Low', 'gte': 0.0, 'lt': 4.0} 
]

# Initialize counts for each VPR range
vpr_counts = {range['name']: 0 for range in vpr_ranges}

# Set the vulnerability states to include 'OPEN' and 'REOPENED'
vulnerability_states = ["OPEN", "REOPENED"]

# Retrieve vulnerabilities for each VPR range
print("Retrieving vulnerabilities...")
for vpr_range in vpr_ranges:
    print(f"Initiating vulnerability export for {vpr_range['name']} VPR range...")
    vpr_score_query = {'gte': vpr_range['gte']}
    if 'lte' in vpr_range:
        vpr_score_query['lte'] = vpr_range['lte']
    if 'lt' in vpr_range:
        vpr_score_query['lt'] = vpr_range['lt']
    export = tio.exports.vulns(vpr_score=vpr_score_query,
                               state=vulnerability_states)
    vulnerabilities = list(export)

    # Count the vulnerabilities in this VPR range
    vpr_counts[vpr_range['name']] = len(vulnerabilities)

# Display the VPR counts for each VPR range
print("\nVPR Counts by Range:")
for range_name, count in vpr_counts.items():
    print(f"{range_name}: {count} vulnerabilities")
