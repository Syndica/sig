import requests 
import re 
import json

def get_frozen_abi_commit(commit):
    url_base = f"https://raw.githubusercontent.com/anza-xyz/agave/{commit}/"
    return get_frozen_abi_base(url_base)

def get_frozen_abi_tag(tag):
    url_base = f"https://raw.githubusercontent.com/anza-xyz/agave/{tag}/"
    return get_frozen_abi_base(url_base)

def get_frozen_abi_base(url_base):
    path = "gossip/src/cluster_info.rs"
    full_url = url_base + path
    print("scraping url: {}".format(full_url))

    r = requests.get(full_url)
    match_str = "frozen_abi\(digest = \"(.*)\"\)"
    abi = re.search(match_str, r.text).groups()[0]
    return abi

last_stable_commit = "09241ae9c341b4434d63371d8696ccba837ef3c1"
stable_abi = get_frozen_abi_commit(last_stable_commit)
# watch master 
latest_abi = get_frozen_abi_tag("master")

if (stable_abi != latest_abi): 
    print("ERROR: Abi mismatch! stable: {}, latest: {}".format(stable_abi, latest_abi))
    exit(1)
else: 
    print("SUCCESS: Abi match! stable: {}, latest: {}".format(stable_abi, latest_abi))
    exit(0)
