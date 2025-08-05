import re
import json
import os
import hashlib
import requests
from datetime import datetime

# Output directories
OUTPUT_DIR = "leaks_scan_results"
CREDS_DIR = os.path.join(OUTPUT_DIR, "credentials")
DOCS_DIR = os.path.join(OUTPUT_DIR, "downloaded_docs")
os.makedirs(CREDS_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)

# Credential patterns
PATTERNS = [
    (r'(email|e-mail|mail)\s*[:=]\s*[\'"]([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\'"]', 'Email'),
    (r'(password|pass|pwd)\s*[:=]\s*[\'"]([^\'"]+)[\'"]', 'Password'),
    (r'(phone|mobile|contact)\s*[:=]\s*[\'"]([\d\+\-\(\)\s]{7,})[\'"]', 'Phone'),
    (r'(name|fullname|username)\s*[:=]\s*[\'"]([a-zA-Z\s\.]+)[\'"]', 'Name'),
    (r'(credit|card|cc)\s*[:=]\s*[\'"]([\d\s-]{13,19})[\'"]', 'CreditCard'),
    (r'(ssn|social\s*security)\s*[:=]\s*[\'"]([\d-]{9,})[\'"]', 'SSN'),
    (r'(api[._-]?key|secret[._-]?key)\s*[:=]\s*[\'"]([^\'"]+)[\'"]', 'API_Key'),
]

def download_sql(url):
    """Download SQL file from URL"""
    try:
        print(f"\nDownloading {url}...")
        local_file = os.path.join(OUTPUT_DIR, os.path.basename(url))
        
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(local_file, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        
        print(f"Saved to {local_file}")
        return local_file
    except Exception as e:
        print(f"Download failed: {str(e)}")
        return None

def extract_credentials(sql_content):
    """Extract credentials from SQL content"""
    results = {
        'emails': set(),
        'passwords': set(),
        'phones': set(),
        'names': set(),
        'credit_cards': set(),
        'ssns': set(),
        'api_keys': set()
    }

    # Find all INSERT statements
    inserts = re.finditer(
        r'INSERT\s+INTO\s+`?(\w+)`?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)',
        sql_content,
        re.IGNORECASE
    )

    for match in inserts:
        columns = [col.strip().strip('`\'"') for col in match.group(2).split(',')]
        values = [val.strip().strip('\'"') for val in re.split(r''',(?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', match.group(3))]
        
        if len(columns) != len(values):
            continue

        record = dict(zip(columns, values))
        
        # Check each field for credentials
        for field, value in record.items():
            for pattern, cred_type in PATTERNS:
                matches = re.finditer(pattern, f"{field}={value}", re.IGNORECASE)
                for m in matches:
                    cred_value = m.group(2) if len(m.groups()) > 1 else m.group(1)
                    if cred_type == 'Email':
                        results['emails'].add(cred_value)
                    elif cred_type == 'Password':
                        results['passwords'].add(cred_value)
                    elif cred_type == 'Phone':
                        results['phones'].add(cred_value)
                    elif cred_type == 'Name':
                        results['names'].add(cred_value)
                    elif cred_type == 'CreditCard':
                        results['credit_cards'].add(cred_value)
                    elif cred_type == 'SSN':
                        results['ssns'].add(cred_value)
                    elif cred_type == 'API_Key':
                        results['api_keys'].add(cred_value)

    return results

def save_results(results, source_name):
    """Save results to organized files"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{source_name}_{timestamp}.json"
    
    # Convert sets to lists for JSON
    report = {k: sorted(v) for k, v in results.items()}
    
    with open(os.path.join(CREDS_DIR, filename), 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nResults saved to {os.path.join(CREDS_DIR, filename)}")

def show_menu():
    """Display simple text menu"""
    print("\n" + "="*40)
    print("LEAKED SQL PROCESSOR")
    print("="*40)
    print("1. Enter URL of SQL file to download and scan")
    print("2. Show saved results")
    print("3. Exit")
    print("="*40)
    
    try:
        choice = int(input("Select option (1-3): "))
        return choice
    except ValueError:
        return -1

def list_results():
    """Show available result files"""
    print("\nAvailable scan results:")
    files = [f for f in os.listdir(CREDS_DIR) if f.endswith('.json')]
    
    if not files:
        print("No results found")
        return
    
    for i, f in enumerate(files, 1):
        print(f"{i}. {f}")
    
    print(f"{len(files)+1}. Back to main menu")
    
    try:
        choice = int(input("Select file to view (or back): "))
        if choice == len(files)+1:
            return
        elif 1 <= choice <= len(files):
            with open(os.path.join(CREDS_DIR, files[choice-1])) as f:
                data = json.load(f)
                print("\n" + "="*40)
                print(f"Contents of {files[choice-1]}:")
                print("="*40)
                for cred_type, values in data.items():
                    print(f"\n{cred_type.upper()} ({len(values)} found):")
                    for v in values[:5]:  # Show first 5 as sample
                        print(f"- {v}")
                    if len(values) > 5:
                        print(f"... and {len(values)-5} more")
    except (ValueError, IndexError):
        print("Invalid selection")

def main():
    while True:
        choice = show_menu()
        
        if choice == 1:
            url = input("\nEnter URL of SQL file: ").strip()
            if not url.startswith(('http://', 'https://')):
                print("Invalid URL - must start with http:// or https://")
                continue
            
            # Download file
            sql_file = download_sql(url)
            if not sql_file:
                continue
            
            # Process file
            print("\nScanning for credentials...")
            with open(sql_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            results = extract_credentials(content)
            source_name = os.path.splitext(os.path.basename(sql_file))[0]
            save_results(results, source_name)
            
            # Show summary
            print("\nScan complete. Found:")
            for cred_type, values in results.items():
                print(f"- {cred_type}: {len(values)}")
            
        elif choice == 2:
            list_results()
        elif choice == 3:
            print("\nExiting...")
            break
        else:
            print("\nInvalid choice - please enter 1, 2 or 3")

if __name__ == "__main__":
    main()
