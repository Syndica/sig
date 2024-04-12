import requests 
import re 
import json

def get_frozen_abi(tag="master"):
    url_base = f"https://raw.githubusercontent.com/anza-xyz/agave/{tag}/"
    path = "gossip/src/cluster_info.rs"

    # print(url_base + path)
    print(url_base + path)
    r = requests.get(url_base + path)
    match_str = "frozen_abi\(digest = \"(.*)\"\)"
    abi = re.search(match_str, r.text).groups()[0]
    return abi

def get_latest_tag(): 
    releases_url = "https://api.github.com/repos/anza-xyz/agave/releases"
    r = requests.get(releases_url)
    d = json.loads(r.text)
    latest_tag = d[0]["html_url"].split("/")[-1]
    return latest_tag

last_stable_tag = "v1.17.29"
stable_abi = get_frozen_abi(last_stable_tag)
# watch master 
latest_abi = get_frozen_abi()

if (stable_abi != latest_abi): 
    print("ERROR: Abi mismatch! stable: {}, latest: {}".format(stable_abi, latest_abi))
    exit(1)
else: 
    print("SUCCESS: Abi match! stable: {}, latest: {}".format(stable_abi, latest_abi))
    exit(0)
