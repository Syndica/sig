# TODO: Last written for 31b6111c

# Current Status Overview
Currently, the `system_program` has been implemented along with basic test cases. For now, it is probably best to comence the implementation of other native programs rather than focusing on rigorous testing of the `system_program`. A [Github issue](https://github.com/Syndica/sig/issues/528) has been opened to address the need for additional system program unit testing. 

The current plan moving forward is to reveiw and merge [system program and related context PR](https://github.com/Syndica/sig/pull/518) and begin the implementation of both the vote (@dadepo) and bpf loader (@yewman) programs. Once the vote and bpf loader programs are implemented, we will consider re-prioritising the implementation of the transaction processing pipeline over more program implementations in order to facilitate @dadepo's work on consensus which may require producing a set of 'state' changes for a given sequence of vote transactions.

# Current Scope

Currently, this document is scoped to the logic contained within the [`execute_loaded_transaction`](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L717) method in Agave. Among other things, this includes: 
- [Initialise TransactionContext](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L753)
- [Initialise InvokeContext](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L782)
- [Execute Transaction](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L798)
- [Determine Status](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L814)
- [Collect Logs](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L841)
- [Collect Instruction Trace](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L848)
- [Collect ExecutionRecord](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L856)
    - accounts: `Vec<(Pubkey, AccountSharedData)>`
    - return_data: `TransactionReturnData`
    - touched_account_count: `u64`
    - accounts_resize_delta: `i64`
- [Check Transaction Balanced](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L863)
- [Return TransactionExecutionResult](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L890)

# Data Structures and Modules

## Account Shared Data
- `AccountSharedData` holds account information with a shared reference to the account data field
- `AccountSharedData`'s are loaded from `accounts_db` during the transaction loading phase
- It should be moved to `accounts_db` at in the future

## Borrowed Account
- `BorrowedAccount` represents an account which has been 'borrowed' from the `TransactionContext`
- It contains the accounts `Pubkey`, a mutable reference to an `AccountSharedData` with an associated single threaded write guard, and a `borrow_context` which represents the context under which account was borrowed
- The `borrow_context` is an unamed struct which contains:
    - `program_id: Pubkey`: the program which borrowed the account
    - `is_writable: bool`: whether the account is writable within the program instruction which borrowed the account
- `BorrowedAccount` provides methods for accessing and modifying account state with necessary checks

## InstructionContext
- `InstructionContext` handles all state required for executing a single program instruction
- Functionality is limited to only support the execution of `SystemProgramInstruction`'s and will evolve as more programs are implemented
- It defines the `program_id` of currently executing instruction, an array of `InstructionAccountInfo`'s which contain account meta data, and the `instruction` which is the serialized program instruction
- It provides methods for borrowing accounts from the `TransactionContext`, loading sysvars from the `SysvarCache`, and performing checks during program execution

## TransactionContext
- `TransactionContext` handles all state required for executing a transaction
-  Functionality is limited to only providing access to data required during the execution of a single instruction. In time, functionality will be extended to executing multiple instructions
- It has an array of `TransactionAccount`'s which contain the account `Pubkey`, and `AccountSharedData`, as well as constructs for basic single threaded read/write locking of the `AccountSharedData`
- These accounts are borrowed by programs during execution in order to perform state changes
- For convenience, it contains dependencies that are required for transaction execution but should ultimately be located in a broader context. For example:
    - `sysvar_cache`
    - `lamports_per_signature`
    - `last_blockhash`
    - `feature_set`

## Feature Set
- `FeatureSet` is used to perform inference on currently active features during program execution
- It should exist above the `TransactionContext`, however, it is defined here for convenience at present
- Its implementation is trivial and does not include any feature definitions yet

## Ids
- `ids` module defines system id's for programs, sysvars and other reserved accounts
- The id defenitions are re-exported from relevant data structures where necessary
- Perhaps they do not all need to be defined in one location, however, it is convenient for reference

## Log Collector
- `LogCollector` is used to collect logs at the transaction level
- Each `TransactionContext` has its own log collector which may be used to collect and emit logs as part of the transaction processing result

## Nonce
- `nonce` implements types for nonce accounts
- It probably belongs somewhere other than `src/runtime/nonce.zig`, perhaps in an SDK of some sort when we get to it

## Pubkey Utils
- `pubkey_utils` defines the `createWithSeed` method which creates a `Pubkey` from a given `base`, `seed`, and `owner`
- It returns a `PubkeyError` on failure which is set as a custom error in the `TransactionContext` when failure occures during program execution
- We may consider moving this logic to `src/core/pubkey.zig`

## SysvarCache 
- `SysvarCache` provides the runtime with access to sysvars during program execution
- Currently its implementation is trivial, and only serves to facilitate an equivalent implementation of Agave's [get_sysvar_with_account_check](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/sysvar_cache.rs#L229) module

## Tmp Utils 
- `tmp_utils` currently only redefines the `hashv` method which is currently defined in `src/ledger/shred.zig`
- Rather than import from this location, the current approach was chosen to emphasize the need to extract this method to an appropriate module
- The extraction is not performed as part of the current PR to simplify review, keeping `refactor` and `feature` implementations separate
