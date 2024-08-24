import re
import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY: str = os.getenv('VT_API_KEY')

url_scanner_url = "https://www.virustotal.com/api/v3/urls"

payload = { "url": "wikipedia.org" }
headers = {
    "accept": "application/json",
    "x-apikey": VT_API_KEY,
    "content-type": "application/x-www-form-urlencoded"
}


#regex for detecting URLs was taken from GeeksForGeeks (may not be the option) https://www.geeksforgeeks.org/python-check-url-string/
url_regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"


async def get_response(user_response: str) -> str:
    lowered_input: str = user_response.lower()

    if urls := check_for_urls(lowered_input):
        print("In get_response: URL detected")
        response = await requests.post(url_scanner_url, data={"url":urls[0]}, headers=headers) #Just scans first URL for now
        return get_id_from_response(response.text)
    return 
    
def check_for_urls(input: str) -> list:
    urls = re.findall(url_regex, input)
    return [url[0] for url in urls] #this is necessary because re.findall returns a list of tuples

if __name__ == "__main__":
    print("HEADERS: " + headers)
    response = requests.post(url_scanner_url, data=payload, headers=headers)
    response_dict = json.loads(response.text)
    analysis_id = response_dict["data"]["id"]
    print("ID: " + analysis_id)

def get_id_from_response(response_text: str) -> str:
    response_dict = json.loads(response_text)
    analysis_id = response_dict["data"]["id"]
    return analysis_id