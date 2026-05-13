import requests
import os
import random

for i in range(10):
    try:
        data = os.urandom(random.randint(10, 50))
        requests.post("http://127.0.0.1:8080", data=data, timeout=1)
        print("Sent random data")
    except:
        pass
