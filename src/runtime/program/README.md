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