'''
This script can be used to generate a minimal subset of accounts needed to
execute a block (for testing as in replay/service.zig).

Filters the accounts from a dump of all accounts used during a block's execution
to exclude entries from that slot.

This keeps the first instance of an account that appears in the input list with
a slot less the slot of the current block (the exclusive upper bound passed in
the cli).
'''
import json
import sys

path = sys.argv[1]
exclusive_upper_bound_slot = int(sys.argv[2])

with open(sys.argv[1]) as f:
    accounts = json.load(f)

seen = set()
filtered_accounts = []
for account in accounts:
    if account['slot'] < exclusive_upper_bound_slot and account['pubkey'] not in seen:
        filtered_accounts.append(account)
        seen.add(account['pubkey'])


with open(path[:-5] + '.filtered.json', 'w') as f:
    json.dump(filtered_accounts, f)
