# Runtime Implementations

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

## ExecuteTransactionContext


## ExecuteTransactionContext 
ExecuteTransactionContext is the **top** level context we will work with for the moment. Any data which is required for transaction execution will be injected into this context, later down the track if it simplifies, or improves the implementation we can extract such data into other context management structs.

ExecuteTransactionContext's responsibilities are similar to the Agave [InvokeContext](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L192).

Functionality will be added to the ExecutionTransactionContext on an as needed basis.

### Account Referencing: Agave

Account references in Agave are held in `InvokeContext.transaction_context.accounts: Rc<TransactionAccounts>` where:
```rust
#[derive(Clone, Debug, PartialEq)]
pub struct TransactionAccounts {
    accounts: Vec<RefCell<AccountSharedData>>,
    touched_flags: RefCell<Box<[bool]>>,
}
```
Transaction accounts (`Vec<(Pubkey, AccountSharedData)>`) are injected into the `TransactionContext` when it is [created](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L753) in the `TransactionBatchProcessor` during `execute_loaded_transaction`. The transaction accounts a read from the `LoadedTransaction` which is generated in the [account loading phase](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L286) which occurs immediately before `execute_loaded_transaction`. 

The key account loading logic can be found [here](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/account_loader.rs#L225-L226) where `AccountSharedData`'s are read from accounts db via [callbacks](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/account_loader.rs#L255-L256). In Agave, the `get_account_shared_data` callback is implemented [here](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/runtime/src/bank.rs#L6799).


## BorrowedAccounts
`BorrowedAccounts` are interesting in that I am not certain why they need to be 'borrowed' yet. A `BorrowedAccount` is simply a write lock over an `AccountSharedData` from the `ExecuteTransactionContext`'s list of accounts along with some other metadata. Since transaction execution is synchronous, I am note sure why we need the write lock here. For now borrowed accounts will keep the lock because both Firedancer and Agave use one so it is likely something I am missing. During instruction execution an account may be 'borrowed' from the transaction execution context, allowing modification of its data.  

## LogCollector
**Implementations**
    - [agave](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L4)
    - [firedancer](https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/log_collector/fd_log_collector.h#L19)
    - [sig](log_collector.zig)

- The `LogCollector` is used to collect logs during transaction execution. 
- The `LogCollector` can be configured with a max log size in bytes.
- Each `ExecuteTransactionContext` has its own log collector.
- Collected logs form part of the `TransactionExecutionResult` and may affect consenus.


## ComputeBudget

## Features

<!-- 

# Borrowed Accounts

fd_executor_load_transaction_accounts: https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/fd_executor.c#L361-L362
fd_executor_setup_borrowed_accounts_for_txn: https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/fd_executor.c#L1439
fd_acc_mgr_view: https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/fd_acc_mgr.c#L131
fd_runtime_finalize_txns_update_blockstore_meta: https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/fd_runtime.c#L968


## Agave: Program Indices
- Loaded for transaction here: https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/svm/src/account_loader.rs#L476-L477
- For each instruction in the transaction:
    - If program is native loader append []; otherwise
    - Load program account and if native loader is the owner append \[program_index\]
- Typed as a Vec\<Vec\<u16\>\> but really a Vec<?u16>
- Returned fro load_transaction as LoadedTransaction.program_indices
- Passed to MessageProcessor::process_message from loaded_transaction 
- Zipped with message instructions iterator for instruction execution 
- Passed to invoke_context.process_instruction
- Used to configure next instruction context

## Agave: Instruction Accounts
- Created in MessageProcessor::process_message
- For each account in the instruction account indexes array:
    - instr.account_indexes = [4, 1, 6]
    - iter (instr_acc_idx, txn_acc_idx): (0, 4)
    - index_in_callee: the index of the first occurence of a particular account
    - index_in_caller: index in transaction 
- InstructionAccounts
    - https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/ledger-tool/src/program.rs#L490
    - https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/program-runtime/src/invoke_context.rs#L377
    - https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/programs/bpf_loader/benches/serialization.rs#L102
    - https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/svm/src/message_processor.rs#L74
    - https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/svm/tests/conformance.rs#387 
    
-->