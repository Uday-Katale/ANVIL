import os
import json
import subprocess
import argparse
from datetime import datetime

def export_traces_via_cli(project_name: str, limit: int = 100, output_file: str = "omium_export.json"):
    """
    Exports traces using the Omium CLI which automatically handles
    authentication, pagination, and config resolution.
    """
    print(f"Exporting up to {limit} traces for project '{project_name}'...")
    
    # Construct the CLI command
    cmd = [
        "omium", "traces", "list",
        "--project", project_name,
        "--limit", str(limit),
        "--output", "json"
    ]
    
    try:
        # Run the command and capture the output
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Parse JSON to ensure it's valid
        data = json.loads(result.stdout)
        
        # Write to the file
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        print(f"✅ Successfully exported {len(data.get('items', data))} traces to {output_file}")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to export traces. CLI Error: {e.stderr}")
    except json.JSONDecodeError:
        print("❌ Failed to parse CLI output as JSON. Check your Omium CLI configuration.")

def export_traces_via_api(project_name: str, limit: int = 100, output_file: str = "omium_export.json"):
    """
    Exports traces directly using the HTTP REST API.
    Requires the OMIUM_API_KEY environment variable to be set.
    """
    import requests
    
    api_key = os.getenv("OMIUM_API_KEY")
    if not api_key:
        print("❌ Error: OMIUM_API_KEY environment variable is not set.")
        return
        
    base_url = os.getenv("OMIUM_API_URL", "https://api.omium.ai")
    endpoint = f"{base_url}/traces"
    
    print(f"Fetching traces from {endpoint}...")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    params = {
        "project": project_name,
        "limit": limit
    }
    
    try:
        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json()
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        print(f"✅ Successfully exported traces to {output_file}")
        
    except requests.exceptions.RequestException as e:
        print(f"❌ API Request failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export raw trace data from Omium")
    parser.add_argument("--project", default="A.E.G.I.S.", help="The Omium project name to export")
    parser.add_argument("--limit", type=int, default=100, help="Max number of traces to fetch")
    parser.add_argument("--method", choices=["cli", "api"], default="cli", 
                        help="Method to use for export (cli is recommended as it uses your local auth)")
    parser.add_argument("--out", help="Output JSON file name")
    
    args = parser.parse_args()
    
    # Generate default output filename with timestamp if not provided
    if not args.out:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.out = f"traces_{args.project}_{timestamp}.json"
        
    if args.method == "cli":
        export_traces_via_cli(args.project, args.limit, args.out)
    else:
        export_traces_via_api(args.project, args.limit, args.out)
