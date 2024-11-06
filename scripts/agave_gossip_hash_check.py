import requests
import re


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
    match_str = 'frozen_abi\(digest = "(.*)"\)'
    abi = re.search(match_str, r.text).groups()[0]
    return abi


last_stable_commit = "af03b1d2de1602e9ede20fdf1d497ad96f475461"
stable_abi = get_frozen_abi_commit(last_stable_commit)
# watch master
latest_abi = get_frozen_abi_tag("master")

if stable_abi != latest_abi:
    print("ERROR: Abi mismatch! stable: {}, latest: {}".format(stable_abi, latest_abi))
    exit(1)
else:
    print("SUCCESS: Abi match! stable: {}, latest: {}".format(stable_abi, latest_abi))
    exit(0)
