import requests

API_KEY = "ea313bac5df4933aadae284c9562a35a2e6533cf43da6d17b6db2abc99b6d91d62b12000c972ca1e"

IP = "185.220.101.1"

url = "https://api.abuseipdb.com/api/v2/check"

headers = {
    "Key": API_KEY,
    "Accept": "application/json"
}

params = {
    "ipAddress": IP,
    "maxAgeInDays": 90
}

response = requests.get(
    url,
    headers=headers,
    params=params
)

print(response.json())
