<!-- 
## ExecuteTransactionContext 
**Implementations**
    - ([agave-InvokeContext](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L192-L193), [agave-TransactionContext](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L136))
    - [firedance](https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/context/fd_exec_txn_ctx.h#L59)
    - [sig](execute_transaction_context.zig)
- ExecuteTransactionContext is the **top** level context we will work with for the moment. Any data which is required for transaction execution will be injected into this context, later down the track if it simplifies or improves the implementation we can extract dependencies into higher level contexts.
- ExecuteTransactionContext's responsibilities are similar to the Agave [InvokeContext](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L192).
- Functionality will be added to the ExecutionTransactionContext on an as needed basis

### Account Referencing

- Account references in Agave are held in `InvokeContext.transaction_context.accounts: Rc<TransactionAccounts>` where:
```rust
#[derive(Clone, Debug, PartialEq)]
pub struct TransactionAccounts {
    accounts: Vec<RefCell<AccountSharedData>>,
    touched_flags: RefCell<Box<[bool]>>,
}
```
- Transaction accounts (`Vec<(Pubkey, AccountSharedData)>`) are injected into the `TransactionContext` when it is [created](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L753) in the `TransactionBatchProcessor` during `execute_loaded_transaction`.
- The transaction accounts are read from the `LoadedTransaction` which is generated during the [account loading phase](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/transaction_processor.rs#L286) which occurs immediately before `execute_loaded_transaction`. 
- The key account loading logic can be found [here](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/account_loader.rs#L225-L226) where `AccountSharedData`'s are read from accounts db via [callbacks](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/svm/src/account_loader.rs#L255-L256).
- In Agave, the `get_account_shared_data` callback is implemented [here](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/runtime/src/bank.rs#L6799).


## BorrowedAccounts
**Implementations**
    - [agave](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L706)
    - [firedance](https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/fd_borrowed_account.h#L11)
    - [sig](borrowed_account.zig)
- A `BorrowedAccount` is simply a write lock over an `AccountSharedData` from the `ExecuteTransactionContext`'s list of accounts
- During instruction execution an account may be 'borrowed' from the transaction execution context, allowing modification of its data.  

## LogCollector
**Implementations**
    - [agave](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L4)
    - [firedancer](https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/log_collector/fd_log_collector.h#L19)
    - [sig](log_collector.zig)

- The `LogCollector` is used to collect logs during transaction execution. 
- The `LogCollector` can be configured with a max log size in bytes.
- Each `ExecuteTransactionContext` has its own log collector.
- Collected logs form part of the `TransactionExecutionResult` and may affect consenus. -->
