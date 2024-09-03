# service.zig: Transaction Sender Service

- The transaction sender is responsible for sending transactions to the leader's TPU for incorporation into the ledger. It must have up to date information about who the current and future leaders are so that it can successfuly get transactions onto the ledger before they expire. 

- The transaction sender receives transaction information from a channel, sends the transactions to the leader TPU addresses and then adds the transactions to a pool where they are retried until they are either expired, failed, or rooted. 

## transaction_info.zig :TransactionInfo
- TransactionInfo is a wrapper around a serialised transaction which includes additional information need to send the transaction such as tracking retries and expiration.

- TODO: `durable_nonce_info` research / usage

## transaction_pool.zig: TransactionPool
- TransactionPool keeps a record of pending transactions, it also provides methods for safely accessing the underlying pending transaction data while sending retries.

## leader_info.zig: LeaderInfo
- LeaderInfo uses and rpc client and gossip table reference to fetch and maintain the leader schedule as well as the leader tpu addresses.
- Its core functionality is to provide a list of the next N leaders tpu addresses, where N is configured in the service config by `max_leaders_to_send_to`

## mock_transfer_generator.zig: Mock Transfer Generator 
- This is a temporary testing service used to confirm that transactions land on chain successfully.
- It simply sends small transfer instructions between two tesnet accounts to a channel
