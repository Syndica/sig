# Program Implementations
- The following document will be used to document native programs and keep track of their implementation progress.
- Ultimately it is intended to serve as a useful reference for understanding all native programs.

## Address Lookup Table Program 
- [ ] address_lookup_table_program
    <!-- Exists in local wip branch
    - [x] Error
    - [ ] Instruction
        - [x] Definitions
        - [ ] Serialise / Deserialise
        - [ ] SDK / Testing Constructors
    - [ ] State 
    -->
- [ ] address_lookup_table_program_execute

## Bpf Loader Program
- [ ] bpf_loader_program
    <!-- Exists in local wip branch
    - [x] BpfLoaderV1 - Deprecated
    - [ ] BpfLoaderV2
        - [ ] Instruction
            - [ ] Definitions
            - [ ] Serialise / Deserialise
            - [ ] SDK / Testing Constructors
    - [ ] BpfLoaderV3
        - [ ] Instruction
            - [ ] Definitions
            - [ ] Serialise / Deserialise
            - [ ] SDK / Testing Constructors
        - [ ] State 
    -->
- [ ] bpf_loader_program_execute
    - [ ] executeInstruction
        - [ ] executeV2Instruction
        - [ ] executeV3Instruction
        - [ ] executeProgram

## Compute Budget Program
- [ ] compute_budget_program
- [ ] compute_budget_program_execute

## Stake Program
- [ ] stake_program
- [ ] stake_program_execute

## Config Program
- [ ] config_program
- [ ] config_program_execute

## Loader V4 Program
- [ ] loader_v4_program
- [ ] loader_v4_program_execute

## Precompile Programs
- [ ] ed25519Verify
- [ ] secp256k1Verify
- [ ] secp256r1Verify

## Stake Program
- [ ] stake_program
- [ ] stake_program_execute

## System Program
### Progress Tracker
- [ ] system_program
    - [x] Error 
    - [ ] Instruction
        - [x] Definitions
        - [ ] Serialise / Deserialise
        - [ ] SDK / Testing Constructors
- [ ] system_program_execute
    - [ ] executeInstruction
        - [x] executeCreateAccount
        - [x] executeAssign
        - [x] executeTransfer
        - [x] executeCreateAccountWithSeed
        - [ ] executeAdvanceNonceAccount 
        - [ ] executeWithdrawNonceAccount
        - [ ] executeInitializeNonceAccount
        - [ ] executeAuthorizeNonceAccount
        - [x] executeAllocate
        - [x] executeAllocateWithSeed
        - [x] executeAssignWithSeed
        - [x] executeTransferWithSeed
        - [ ] executeUpgradeNonceAccount

### Instructions 
#### Advance Nonce Account
- Consumes a stored nonce, replacing it with a successor
- Account references:

    0. `[WRITE]` Nonce account
    1. `[]` RecentBlockhashes sysvar
    2. `[SIGNER]` Nonce authority
- Instruction must have at least 1 account
- Reads RecentBlockhashes Sysvar and errors if the list is empty 

#### Withdraw Nonce Account
- Withdraw funds from a nonce account

- Account references

   0. `[WRITE]` Nonce account
   1. `[WRITE]` Recipient account
   2. `[]` RecentBlockhashes sysvar
   3. `[]` Rent sysvar
   4. `[SIGNER]` Nonce authority



## Vote Program
- [ ] vote_program
- [ ] vote_program_execute

## Zk Elgamal Proof Program
- [ ] zk_elgamal_proof_program
- [ ] zk_elgamal_proof_program_execute

## Zk Token Proof Program
- [ ] zk_token_proof_program
- [ ] zk_token_proof_program_execute