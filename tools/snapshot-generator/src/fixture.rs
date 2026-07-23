use std::{collections::HashMap, sync::Arc};

use serde::Serialize;
use solana_account::{AccountSharedData, ReadableAccount, WritableAccount};
use solana_accounts_db::{accounts_db::AccountsDb, accounts_hash::AccountLtHash};
use solana_accounts_db::{accounts_hash::AccountsLtHash, blockhash_queue::BlockhashQueue};
use solana_clock::{Epoch, Slot};
use solana_epoch_schedule::EpochSchedule;
use solana_fee_calculator::FeeRateGovernor;
use solana_hard_forks::HardForks;
use solana_hash::Hash;
use solana_inflation::Inflation;
use solana_lattice_hash::lt_hash::LtHash;
use solana_pubkey::Pubkey;
use solana_runtime::stake_account::StakeAccount;
use solana_runtime::{
    bank::BankFieldsToSerialize,
    epoch_stakes::VersionedEpochStakes,
    leader_schedule_utils::leader_schedule_from_vote_accounts,
    serde_snapshot::ExtraFieldsToSerialize,
    stakes::{SerdeStakesToStakeFormat, Stakes},
};
use solana_stake_interface::state::Delegation;
use solana_vote::vote_account::VoteAccounts;
use solana_vote::vote_account::{VoteAccount, VoteAccountsHashMap};

pub const TICKS_PER_SLOT: u64 = 64;

const SLOT: Slot = 100;
const NS_PER_SLOT: u128 = 400_000_000;
const SLOTS_PER_YEAR: f64 = 78_892_314.98630137;

pub struct Fixture {
    pub epoch: Epoch,
    pub accounts: Vec<Account>,
    pub live_accounts: Vec<Account>,
    pub hard_forks_pairs: Vec<(Slot, u64)>,
    // Values generated here but not fully exposed by agave's public views.
    pub main_stake_delegations: Vec<GeneratedStakeDelegation>,
    pub epoch_stakes: Vec<GeneratedEpochStakes>,
}

#[derive(Clone)]
pub struct GeneratedEpochStakes {
    pub epoch: Epoch,
    pub stake_delegations: Vec<GeneratedStakeDelegation>,
}

#[derive(Clone)]
pub struct Account {
    pub slot: Slot,
    pub pubkey: Pubkey,
    pub account: AccountSharedData,
}

pub struct VoteAndStake {
    pub vote_accounts: VoteAccounts,
    pub stake_delegations: Vec<(Pubkey, StakeAccount<Delegation>)>,
    pub accounts: Vec<Account>,
    // Full generated values. Agave's public views hide some of these fields.
    pub generated_stake_delegations: Vec<GeneratedStakeDelegation>,
}

impl Account {
    fn new(
        slot: Slot,
        seed: u8,
        data: Vec<u8>,
        lamports: u64,
        owner: Pubkey,
        rent_epoch: Epoch,
    ) -> Self {
        let pubkey = pubkey(seed);
        let mut account = AccountSharedData::default();
        account.set_lamports(lamports);
        account.set_owner(owner);
        account.set_data(data);
        account.set_rent_epoch(rent_epoch);
        account.set_executable(false);
        Self {
            slot,
            pubkey,
            account,
        }
    }

    pub fn lt_hash(&self) -> AccountLtHash {
        AccountsDb::lt_hash_account(&self.account, &self.pubkey)
    }
}

#[derive(Clone)]
pub struct GeneratedStakeDelegation {
    pub stake_pubkey: Pubkey,
    pub voter_pubkey: Pubkey,
    pub authorized: Pubkey,
    pub stake: u64,
    pub activation_epoch: Epoch,
    pub deactivation_epoch: Epoch,
}

pub fn build_fixture(slot: Slot) -> (Fixture, BankFieldsToSerialize, ExtraFieldsToSerialize) {
    let epoch_schedule = EpochSchedule::default();
    let epoch = epoch_schedule.get_epoch(slot);

    let (mut accounts, mut live_accounts) = build_plain_accounts();
    let VoteAndStake {
        vote_accounts,
        stake_delegations,
        generated_stake_delegations: main_stake_delegations,
        accounts: stake_and_vote_accounts,
    } = build_vote_and_stake_accounts(0x30);
    live_accounts.extend(stake_and_vote_accounts.iter().cloned());
    accounts.extend(stake_and_vote_accounts);
    let rent_sysvar = rent_sysvar_account();
    let slot_history_sysvar = slot_history_sysvar_account();
    live_accounts.push(rent_sysvar.clone());
    live_accounts.push(slot_history_sysvar.clone());
    accounts.push(rent_sysvar);
    accounts.push(slot_history_sysvar);

    let accounts_data_len: u64 = live_accounts
        .iter()
        .map(|a| a.account.data().len() as u64)
        .sum();
    let capitalization: u64 = live_accounts.iter().map(|a| a.account.lamports()).sum();

    let mut lt = LtHash::identity();
    for a in &live_accounts {
        lt.mix_in(&a.lt_hash().0);
    }
    let accounts_lt_hash = AccountsLtHash(lt);
    let stakes = build_stakes(epoch, vote_accounts, stake_delegations);

    let (versioned_epoch_stakes, epoch_stakes) = build_versioned_epoch_stakes(epoch);
    // VersionedEpochStakes isn't Clone. Rebuild with the same seeds for an
    // identical second copy.
    let (versioned_epoch_stakes_extra, _) = build_versioned_epoch_stakes(epoch);

    let mut blockhash_queue = BlockhashQueue::default();
    blockhash_queue.register_hash(&hash(0x40), 5_000);
    blockhash_queue.register_hash(&hash(0x41), 5_000);

    let hard_forks_pairs: Vec<(Slot, u64)> = vec![(10, 1), (50, 1)];
    let mut hard_forks = HardForks::default();
    for (s, _c) in &hard_forks_pairs {
        hard_forks.register(*s);
    }

    let parent_hash = hash(0x22);
    let block_id = hash(0x33);
    let leader_id = slot_leader(slot, &epoch_schedule, &versioned_epoch_stakes);
    let transaction_count = 12_345;
    let signature_count = 6_789;
    let tick_height = (slot + 1) * TICKS_PER_SLOT;
    let hashes_per_tick = Some(12_500);
    let genesis_creation_time = 1_700_000_000i64;
    let bank_lamports_per_signature = 4_750u64;
    let extra_lamports_per_signature = 6_000u64;
    let mut fee_rate_governor = FeeRateGovernor::new(bank_lamports_per_signature, 1);
    fee_rate_governor.lamports_per_signature = bank_lamports_per_signature;

    let bank_hash = bank_hash(
        parent_hash,
        signature_count,
        blockhash_queue.last_hash(),
        &accounts_lt_hash,
        &hard_forks,
        slot,
        slot.saturating_sub(1),
    );

    let bank_fields = BankFieldsToSerialize {
        blockhash_queue,
        hash: bank_hash,
        parent_hash,
        parent_slot: slot.saturating_sub(1),
        hard_forks,
        transaction_count,
        tick_height,
        signature_count,
        capitalization,
        max_tick_height: tick_height,
        hashes_per_tick,
        ticks_per_slot: TICKS_PER_SLOT,
        ns_per_slot: NS_PER_SLOT,
        genesis_creation_time,
        slots_per_year: SLOTS_PER_YEAR,
        slot,
        block_height: slot,
        leader_id,
        fee_rate_governor,
        epoch_schedule,
        inflation: Inflation::default(),
        stakes,
        is_delta: true,
        accounts_data_len,
        versioned_epoch_stakes,
        accounts_lt_hash: accounts_lt_hash.clone(),
        block_id,
    };

    let extra_fields = ExtraFieldsToSerialize {
        lamports_per_signature: extra_lamports_per_signature,
        unused_incremental_snapshot_persistence: None,
        unused_epoch_accounts_hash: None,
        versioned_epoch_stakes: versioned_epoch_stakes_extra,
        accounts_lt_hash: Some(accounts_lt_hash.into()),
        block_id: Some(block_id),
    };

    let fixture = Fixture {
        epoch,
        accounts,
        live_accounts,
        hard_forks_pairs,
        main_stake_delegations,
        epoch_stakes,
    };
    (fixture, bank_fields, extra_fields)
}

fn build_plain_accounts() -> (Vec<Account>, Vec<Account>) {
    let system = pubkey(0);
    let old_a = Account::new(98, 0x11, b"old account data".to_vec(), 900_000, system, 90);
    let live_a = Account::new(100, 0x11, b"account data".to_vec(), 1_000_000, system, 100);
    let live_b = Account::new(99, 0x22, b"another account".to_vec(), 500_000, system, 200);
    (
        vec![old_a, live_b.clone(), live_a.clone()],
        vec![live_b, live_a],
    )
}

fn rent_sysvar_account() -> Account {
    sysvar_account(
        solana_sdk_ids::sysvar::rent::id(),
        &solana_rent::Rent::default(),
    )
}

fn slot_history_sysvar_account() -> Account {
    let mut slot_history = solana_slot_history::SlotHistory::default();
    for slot in crate::slot_history_found_slots(SLOT)
        .into_iter()
        .filter(|slot| *slot != 0)
    {
        slot_history.add(slot);
    }
    sysvar_account(solana_sdk_ids::sysvar::slot_history::id(), &slot_history)
}

fn sysvar_account<T: Serialize>(pubkey: Pubkey, value: &T) -> Account {
    let mut account = AccountSharedData::default();
    account.set_lamports(1);
    account.set_owner(solana_sdk_ids::sysvar::id());
    account.set_data(bincode::serialize(value).unwrap());
    Account {
        slot: SLOT,
        pubkey,
        account,
    }
}

fn build_vote_and_stake_accounts(seed_tag: u8) -> VoteAndStake {
    use solana_rent::Rent;
    use solana_runtime::stake_utils;

    let mk_seed = |b: u8| {
        let mut s = [0u8; 32];
        s[0] = seed_tag;
        s[1] = b;
        s
    };

    let rent = Rent::default();
    let (vote_pk_a, vote_a) = deterministic_vote_account(mk_seed(0x01));
    let (vote_pk_b, vote_b) = deterministic_vote_account(mk_seed(0x02));

    let stake_pk_a = Pubkey::new_from_array(mk_seed(0x11));
    let stake_pk_b = Pubkey::new_from_array(mk_seed(0x12));
    let auth_a = Pubkey::new_from_array(mk_seed(0x21));
    let auth_b = Pubkey::new_from_array(mk_seed(0x22));

    let stake_lamports: u64 = rent.minimum_balance(200) + 1_000_000;
    let mk_stake = |voter: &Pubkey, vote_acc: &VoteAccount, auth: &Pubkey, stake_pk: Pubkey| {
        let acc = stake_utils::create_stake_account(
            auth,
            voter,
            vote_acc.account(),
            &rent,
            stake_lamports,
        );
        let stake_acc: StakeAccount<Delegation> = acc.clone().try_into().expect("stake account");
        (
            stake_pk,
            stake_acc,
            Account {
                slot: SLOT,
                pubkey: stake_pk,
                account: acc,
            },
        )
    };
    let stake_a = mk_stake(&vote_pk_a, &vote_a, &auth_a, stake_pk_a);
    let stake_b = mk_stake(&vote_pk_b, &vote_b, &auth_b, stake_pk_b);
    let stake_delegations = vec![(stake_a.0, stake_a.1), (stake_b.0, stake_b.1)];
    let accounts = vec![
        Account {
            slot: SLOT,
            pubkey: vote_pk_a,
            account: vote_a.account().clone(),
        },
        Account {
            slot: SLOT,
            pubkey: vote_pk_b,
            account: vote_b.account().clone(),
        },
        stake_a.2,
        stake_b.2,
    ];
    let mut va_map: VoteAccountsHashMap = HashMap::new();
    va_map.insert(vote_pk_a, (2_000_000u64, vote_a));
    va_map.insert(vote_pk_b, (3_000_000u64, vote_b));
    let vote_accounts = VoteAccounts::from(Arc::new(va_map));

    let generated_stake_delegations: Vec<GeneratedStakeDelegation> = stake_delegations
        .iter()
        .map(|(pk, sa)| {
            let d = sa.delegation();
            let auth = if *pk == stake_pk_a { auth_a } else { auth_b };
            GeneratedStakeDelegation {
                stake_pubkey: *pk,
                voter_pubkey: d.voter_pubkey,
                authorized: auth,
                stake: d.stake,
                activation_epoch: d.activation_epoch,
                deactivation_epoch: d.deactivation_epoch,
            }
        })
        .collect();
    VoteAndStake {
        vote_accounts,
        stake_delegations,
        accounts,
        generated_stake_delegations,
    }
}

// Mirrors agave/vote/src/vote_account.rs `VoteAccount::new_random` with a
// deterministic seed instead of random keypairs.
fn deterministic_vote_account(seed: [u8; 32]) -> (Pubkey, VoteAccount) {
    use solana_bls_signatures::Keypair as BLSKeypair;
    use solana_clock::Clock;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use solana_vote_interface::state::{
        VoteInitV2, VoteStateV4, VoteStateVersions, BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE,
    };

    let keypair = Keypair::new_from_array(seed);
    let bls_keypair = BLSKeypair::derive_from_signer(&keypair, b"alpenglow").unwrap();

    let vote_init = VoteInitV2 {
        node_pubkey: Pubkey::new_from_array({
            let mut s = seed;
            s[0] ^= 0xA0;
            s
        }),
        authorized_voter: keypair.pubkey(),
        authorized_voter_bls_pubkey: bls_keypair.public.to_bytes_compressed(),
        authorized_voter_bls_proof_of_possession: [0; BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE],
        authorized_withdrawer: Pubkey::new_from_array({
            let mut s = seed;
            s[0] ^= 0xB0;
            s
        }),
        inflation_rewards_commission_bps: 1_000,
        block_revenue_commission_bps: 500,
    };
    let clock = Clock {
        slot: 1,
        epoch_start_timestamp: 1_700_000_000,
        epoch: 0,
        leader_schedule_epoch: 1,
        unix_timestamp: 1_700_000_000,
    };
    let vote_state = VoteStateV4::new(
        &vote_init,
        /* current_authorized_voter */ &keypair.pubkey(),
        /* current_authorized_voter_bls_pubkey */ &keypair.pubkey(),
        &clock,
    );
    let account = AccountSharedData::new_data(
        /* lamports */ 42_000_000,
        &VoteStateVersions::new_v4(vote_state),
        &solana_sdk_ids::vote::id(),
    )
    .unwrap();
    (keypair.pubkey(), VoteAccount::try_from(account).unwrap())
}

fn build_stakes(
    epoch: Epoch,
    vote_accounts: VoteAccounts,
    stake_delegations: Vec<(Pubkey, StakeAccount<Delegation>)>,
) -> Stakes<StakeAccount<Delegation>> {
    let mut stakes: Stakes<StakeAccount<Delegation>> = Stakes {
        vote_accounts,
        unused: 42,
        epoch,
        stake_history: build_stake_history(),
        ..Stakes::default()
    };
    for (pubkey, sa) in stake_delegations {
        stakes.stake_delegations.insert(pubkey, sa);
    }
    stakes
}

fn build_stake_history() -> solana_runtime::stake_history::StakeHistory {
    use solana_runtime::stake_history::StakeHistory;
    use solana_stake_interface::stake_history::StakeHistoryEntry;
    let mut sh = StakeHistory::default();
    sh.add(
        1,
        StakeHistoryEntry {
            effective: 1_000_000,
            activating: 200_000,
            deactivating: 100_000,
        },
    );
    sh.add(
        2,
        StakeHistoryEntry {
            effective: 1_200_000,
            activating: 300_000,
            deactivating: 150_000,
        },
    );
    sh
}

fn build_versioned_epoch_stakes(
    base_epoch: Epoch,
) -> (
    HashMap<u64, VersionedEpochStakes>,
    Vec<GeneratedEpochStakes>,
) {
    let mut generated_epoch_stakes = Vec::new();
    let mut make = |e: Epoch, seed_tag: u8| {
        let VoteAndStake {
            vote_accounts,
            stake_delegations,
            generated_stake_delegations,
            accounts: _,
        } = build_vote_and_stake_accounts(seed_tag);
        generated_epoch_stakes.push(GeneratedEpochStakes {
            epoch: e,
            stake_delegations: generated_stake_delegations,
        });
        let s = build_stakes(e, vote_accounts, stake_delegations);
        VersionedEpochStakes::new(SerdeStakesToStakeFormat::from(s), e)
    };
    let mut out = HashMap::new();
    out.insert(base_epoch, make(base_epoch, 0x40));
    out.insert(base_epoch + 1, make(base_epoch + 1, 0x50));
    (out, generated_epoch_stakes)
}

fn slot_leader(
    slot: Slot,
    epoch_schedule: &EpochSchedule,
    epoch_stakes: &HashMap<u64, VersionedEpochStakes>,
) -> Pubkey {
    let (epoch, slot_index) = epoch_schedule.get_epoch_and_slot_index(slot);
    let vote_accounts = epoch_stakes
        .get(&epoch)
        .expect("missing current epoch stakes")
        .stakes()
        .vote_accounts();
    leader_schedule_from_vote_accounts(epoch, epoch_schedule, vote_accounts.as_ref())
        .expect("leader schedule")
        .get_slot_leader_at_index(slot_index as usize)
        .id
}

fn bank_hash(
    parent_hash: Hash,
    signature_count: u64,
    last_blockhash: Hash,
    accounts_lt_hash: &AccountsLtHash,
    hard_forks: &HardForks,
    slot: Slot,
    parent_slot: Slot,
) -> Hash {
    let mut hash = solana_sha256_hasher::hashv(&[
        parent_hash.as_ref(),
        &signature_count.to_le_bytes(),
        last_blockhash.as_ref(),
    ]);
    hash = solana_sha256_hasher::hashv(&[hash.as_ref(), accounts_lt_hash_bytes(accounts_lt_hash)]);
    if let Some(buf) = hard_forks.get_hash_data(slot, parent_slot) {
        hash = solana_sha256_hasher::hashv(&[hash.as_ref(), &buf]);
    }
    hash
}

fn accounts_lt_hash_bytes(h: &AccountsLtHash) -> &[u8] {
    let AccountsLtHash(lt) = h;
    bytemuck::cast_slice::<u16, u8>(&lt.0)
}

fn pubkey(seed: u8) -> Pubkey {
    Pubkey::new_from_array([seed; 32])
}

fn hash(seed: u8) -> Hash {
    Hash::new_from_array([seed; 32])
}
