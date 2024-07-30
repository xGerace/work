import requests

def update_tor_ips(file_path):
    url = "https://www.dan.me.uk/torlist/exit"
    response = requests.get(url)
    
    if response.status_code == 200:
        with open(file_path, "w") as file:
            file.write(response.text)
        print(f"Successfully updated {file_path}")
    else:
        print(f"Failed to retrieve the list. Status code: {response.status_code}")

if __name__ == "__main__":
    update_tor_ips("tor_ips.txt")