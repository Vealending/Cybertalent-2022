from base64 import b64decode
import requests
import hashlib
import re
import io
import Command


url = "http://shady-aggregator.utl/f52e6101/"
r = requests.get(url + "list")
ids = [line.split('|')[0].strip() for line in r.text.split('\n') if line]
filtered_ids = [id for id in ids if len(id) == 16]
payloads = []

for id in filtered_ids:
    r = requests.get(url + id + "/commands")
    for base64 in re.findall(r'(?<=\n)([A-Za-z0-9+/=]+)(?=\n)', r.text):
        payload = b64decode(base64)
        if payload not in payloads:
            payloads.append(payload)

for payload in payloads:
    try:
        with open(f"cmd_{cmd_object.recipient}_{hashlib.md5(payload).hexdigest()}", "wb") as f:
            f.write(payload)
        fd = io.BytesIO(payload)
        cmd_object = Command.Command(fd)
        print(cmd_object.__str__())
    except Exception as e:
        print("Very likely a Config object. Error:", e)
