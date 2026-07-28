use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{json, Value};
use solana_account::ReadableAccount;
use solana_accounts_db::blockhash_queue::BlockhashQueue;
use solana_clock::Slot;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_runtime::{
    bank::BankFieldsToSerialize, epoch_stakes::VersionedEpochStakes,
    serde_snapshot::ExtraFieldsToSerialize, stake_account::StakeAccount, stakes::Stakes,
};
use solana_stake_interface::state::Delegation;

use crate::fixture::Fixture;
use crate::fixture::GeneratedEpochStakes;
use crate::fixture::GeneratedStakeDelegation;
use crate::AccountFile;

pub fn fixture_json_string(
    f: &Fixture,
    bank: &BankFieldsToSerialize,
    extra: &ExtraFieldsToSerialize,
    status_cache: Value,
    account_files: &[AccountFile],
) -> String {
    let root = json!({
        "bank_fields": bank_fields_json(f, bank),
        "extra_fields": extra_fields_json(f, extra),
        "merged_fields": merged_fields_json(f, bank, extra),
        "accounts": accounts_json(f, account_files),
        "status_cache": status_cache,
    });
    serde_json::to_string_pretty(&root).unwrap()
}

pub fn hex_line(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn bank_fields_json(f: &Fixture, bank: &BankFieldsToSerialize) -> Value {
    let g = &bank.fee_rate_governor;
    let es = &bank.epoch_schedule;
    let inf = &bank.inflation;

    json!({
        "slot": bank.slot,
        "epoch": f.epoch,
        "parent_slot": bank.parent_slot,
        "block_height": bank.block_height,
        "hash": bank.hash.to_string(),
        "parent_hash": bank.parent_hash.to_string(),
        "leader_id": bank.leader_id.to_string(),
        "transaction_count": bank.transaction_count,
        "signature_count": bank.signature_count,
        "tick_height": bank.tick_height,
        "max_tick_height": bank.max_tick_height,
        "ticks_per_slot": bank.ticks_per_slot,
        "hashes_per_tick": bank.hashes_per_tick,
        "ns_per_slot": bank.ns_per_slot as u64,
        "slots_per_year": bank.slots_per_year,
        "genesis_creation_time": bank.genesis_creation_time,
        "accounts_data_len": bank.accounts_data_len,
        "capitalization": bank.capitalization,
        "is_delta": bank.is_delta,

        "fee_rate_governor": {
            "lamports_per_signature": g.lamports_per_signature,
            "target_lamports_per_signature": g.target_lamports_per_signature,
            "target_signatures_per_slot": g.target_signatures_per_slot,
            "min_lamports_per_signature": g.min_lamports_per_signature,
            "max_lamports_per_signature": g.max_lamports_per_signature,
            "burn_percent": g.burn_percent,
        },

        "epoch_schedule": {
            "slots_per_epoch": es.slots_per_epoch,
            "leader_schedule_slot_offset": es.leader_schedule_slot_offset,
            "warmup": es.warmup,
            "first_normal_epoch": es.first_normal_epoch,
            "first_normal_slot": es.first_normal_slot,
        },

        "inflation": {
            "initial": inf.initial,
            "terminal": inf.terminal,
            "taper": inf.taper,
            "foundation": inf.foundation,
            "foundation_term": inf.foundation_term,
        },

        "blockhash_queue": blockhash_queue_json(&bank.blockhash_queue),
        "hard_forks": hard_forks_json(&f.hard_forks_pairs),
        "stakes": stakes_json(&bank.stakes, &f.main_stake_delegations),
    })
}

fn extra_fields_json(f: &Fixture, extra: &ExtraFieldsToSerialize) -> Value {
    let uisp = extra
        .unused_incremental_snapshot_persistence
        .as_ref()
        .map(|p| {
            json!({
                "full_slot": p.full_slot,
                "full_hash_hex": hex_line(&p.full_hash),
                "full_capitalization": p.full_capitalization,
                "incremental_hash_hex": hex_line(&p.incremental_hash),
                "incremental_capitalization": p.incremental_capitalization,
            })
        });

    let ueah = extra
        .unused_epoch_accounts_hash
        .as_ref()
        .map(|h| hex_line(h.as_ref()));

    json!({
        "lamports_per_signature": extra.lamports_per_signature,
        "block_id": extra.block_id.map(|h| h.to_string()),
        "unused_incremental_snapshot_persistence": uisp,
        "unused_epoch_accounts_hash": ueah,
        "versioned_epoch_stakes": versioned_epoch_stakes_array(f, &extra.versioned_epoch_stakes),
        "accounts_lt_hash": extra
            .accounts_lt_hash
            .as_ref()
            .map(|h| hex_line(bytemuck::cast_slice::<u16, u8>(&h.0))),
    })
}

fn merged_fields_json(
    f: &Fixture,
    bank: &BankFieldsToSerialize,
    extra: &ExtraFieldsToSerialize,
) -> Value {
    let mut merged = bank_fields_json(f, bank);
    let obj = merged.as_object_mut().unwrap();
    obj.insert(
        "block_id".to_string(),
        json!(extra.block_id.map(|h| h.to_string())),
    );
    obj.insert(
        "versioned_epoch_stakes".to_string(),
        versioned_epoch_stakes_array(f, &extra.versioned_epoch_stakes),
    );
    obj.insert(
        "accounts_lt_hash".to_string(),
        json!(extra
            .accounts_lt_hash
            .as_ref()
            .map(|h| hex_line(bytemuck::cast_slice::<u16, u8>(&h.0)))),
    );
    obj.insert(
        "slot_history_found_slots".to_string(),
        json!(crate::slot_history_found_slots(bank.slot)),
    );
    obj.get_mut("fee_rate_governor")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "lamports_per_signature".to_string(),
            json!(extra.lamports_per_signature),
        );
    merged
}

fn versioned_epoch_stakes_array(f: &Fixture, stakes: &HashMap<u64, VersionedEpochStakes>) -> Value {
    let mut ves = Vec::new();
    let mut epochs: Vec<u64> = stakes.keys().copied().collect();
    epochs.sort();
    for e in epochs {
        let generated_epoch_stakes = f
            .epoch_stakes
            .iter()
            .find(|a| a.epoch == e)
            .expect("missing generated epoch stakes");
        ves.push(versioned_epoch_stakes_json(
            e,
            stakes.get(&e).unwrap(),
            generated_epoch_stakes,
        ));
    }
    Value::Array(ves)
}

fn blockhash_queue_json(q: &BlockhashQueue) -> Value {
    #[derive(Deserialize)]
    struct HashInfoMirror {
        lamports_per_signature: u64,
        hash_index: u64,
        timestamp: u64,
    }
    #[derive(Deserialize)]
    struct BlockhashQueueMirror {
        last_hash_index: u64,
        last_hash: Option<Hash>,
        hashes: Vec<(Hash, HashInfoMirror)>,
        max_age: usize,
    }

    // `BlockhashQueue.hashes` and `HashInfo.timestamp` have no pub accessor.
    // Round-trip through bincode to read them.
    let bytes = bincode::serialize(q).expect("serialize BlockhashQueue");
    let m: BlockhashQueueMirror =
        bincode::deserialize(&bytes).expect("deserialize BlockhashQueueMirror");

    let mut sorted = m.hashes;
    sorted.sort_by_key(|(k, _)| k.to_bytes());
    let hashes: Vec<Value> = sorted
        .into_iter()
        .map(|(hash, info)| {
            json!({
                "hash": hash.to_string(),
                "lamports_per_signature": info.lamports_per_signature,
                "hash_index": info.hash_index,
                "timestamp_ms": info.timestamp,
            })
        })
        .collect();
    json!({
        "last_hash_index": m.last_hash_index,
        "last_hash": m.last_hash.map(|h| h.to_string()),
        "max_age": m.max_age,
        "hashes": hashes,
    })
}

fn hard_forks_json(pairs: &[(Slot, u64)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(s, c)| json!({"slot": s, "count": c}))
            .collect(),
    )
}

fn stakes_json(
    s: &Stakes<StakeAccount<Delegation>>,
    generated_stake_delegations: &[GeneratedStakeDelegation],
) -> Value {
    let mut vote_sorted: Vec<_> = s.vote_accounts.iter().collect();
    vote_sorted.sort_by_key(|(k, _)| k.to_bytes());
    let vote_accounts: Vec<Value> = vote_sorted
        .into_iter()
        .map(|(pk, va)| {
            let acc = va.account();
            json!({
                "vote_pubkey": pk.to_string(),
                "stake": s.vote_accounts.get_delegated_stake(pk),
                "node_pubkey": va.node_pubkey().to_string(),
                "lamports": acc.lamports(),
                "owner": acc.owner().to_string(),
                "executable": acc.executable(),
                "rent_epoch": acc.rent_epoch(),
                "vote_state_data_len": acc.data().len(),
            })
        })
        .collect();

    let mut sd_sorted: Vec<(&Pubkey, &StakeAccount<Delegation>)> =
        s.stake_delegations.iter().collect();
    sd_sorted.sort_by_key(|(k, _)| k.to_bytes());
    let stake_delegations: Vec<Value> = sd_sorted
        .into_iter()
        .map(|(pk, sa)| {
            let d = sa.delegation();
            let auth = generated_stake_delegations
                .iter()
                .find(|a| a.stake_pubkey == *pk)
                .expect("missing generated stake delegation")
                .authorized;
            json!({
                "stake_pubkey": pk.to_string(),
                "voter_pubkey": d.voter_pubkey.to_string(),
                "authorized": auth.to_string(),
                "stake": d.stake,
                "activation_epoch": d.activation_epoch,
                "deactivation_epoch": d.deactivation_epoch,
            })
        })
        .collect();

    let stake_history: Vec<Value> = s
        .stake_history
        .iter()
        .map(|(epoch, e)| {
            json!({
                "epoch": epoch,
                "effective": e.effective,
                "activating": e.activating,
                "deactivating": e.deactivating,
            })
        })
        .collect();

    json!({
        "epoch": s.epoch,
        "unused": s.unused,
        "vote_accounts": vote_accounts,
        "stake_delegations": stake_delegations,
        "stake_history": stake_history,
    })
}

fn versioned_epoch_stakes_json(
    epoch: u64,
    ves: &VersionedEpochStakes,
    generated_epoch_stakes: &GeneratedEpochStakes,
) -> Value {
    let va = ves.stakes().vote_accounts();
    let mut sorted: Vec<_> = va.iter().collect();
    sorted.sort_by_key(|(k, _)| k.to_bytes());
    let vote_accounts: Vec<Value> = sorted
        .into_iter()
        .map(|(pk, v)| {
            json!({
                "vote_pubkey": pk.to_string(),
                "stake": va.get_delegated_stake(pk),
                "node_pubkey": v.node_pubkey().to_string(),
                "lamports": v.account().lamports(),
                "owner": v.account().owner().to_string(),
            })
        })
        .collect();

    let mut sorted = generated_epoch_stakes.stake_delegations.clone();
    sorted.sort_by_key(|e| e.stake_pubkey.to_bytes());
    let stake_delegations = Value::Array(
        sorted
            .into_iter()
            .map(|e| {
                json!({
                    "stake_pubkey": e.stake_pubkey.to_string(),
                    "voter_pubkey": e.voter_pubkey.to_string(),
                    "authorized": e.authorized.to_string(),
                    "stake": e.stake,
                    "activation_epoch": e.activation_epoch,
                    "deactivation_epoch": e.deactivation_epoch,
                })
            })
            .collect(),
    );

    let nvm = ves.node_id_to_vote_accounts();
    let mut sorted: Vec<_> = nvm.iter().collect();
    sorted.sort_by_key(|(k, _)| k.to_bytes());
    let node_id_to_vote_accounts: Vec<Value> = sorted
        .into_iter()
        .map(|(node, nv)| {
            json!({
                "node_id": node.to_string(),
                "total_stake": nv.total_stake,
                "vote_pubkeys": nv.vote_accounts.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            })
        })
        .collect();

    let eav = ves.epoch_authorized_voters();
    let mut sorted: Vec<_> = eav.iter().collect();
    sorted.sort_by_key(|(k, _)| k.to_bytes());
    let epoch_authorized_voters: Vec<Value> = sorted
        .into_iter()
        .map(|(vote_pk, voter)| {
            json!({
                "vote_pubkey": vote_pk.to_string(),
                "authorized_voter": voter.to_string(),
            })
        })
        .collect();

    json!({
        "epoch": epoch,
        "variant": "Current",
        "total_stake": ves.total_stake(),
        "vote_accounts": vote_accounts,
        "stake_delegations": stake_delegations,
        "node_id_to_vote_accounts": node_id_to_vote_accounts,
        "epoch_authorized_voters": epoch_authorized_voters,
    })
}

fn accounts_json(f: &Fixture, account_files: &[AccountFile]) -> Value {
    let files: Vec<Value> = account_files
        .iter()
        .map(|f| {
            json!({
                "slot": f.slot,
                "id": f.id,
                "path": format!("accounts/{}.{}", f.slot, f.id),
                "on_disk_size": f.bytes.len(),
            })
        })
        .collect();

    let entries: Vec<Value> = f
        .accounts
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let d = a.account.data();
            let lt = a.lt_hash().0;
            let lt_bytes = bytemuck::cast_slice::<u16, u8>(&lt.0);
            let file_id = account_files
                .iter()
                .find(|file| file.slot == a.slot)
                .expect("missing account file")
                .id;
            json!({
                "index": i,
                "slot": a.slot,
                "file_id": file_id,
                "pubkey": a.pubkey.to_string(),
                "lamports": a.account.lamports(),
                "owner": a.account.owner().to_string(),
                "executable": a.account.executable(),
                "rent_epoch": a.account.rent_epoch(),
                "data_len": d.len(),
                "data_hex": hex_line(d),
                "data_utf8": std::str::from_utf8(d).ok(),
                "account_lt_hash_first_32_hex": hex_line(&lt_bytes[..32]),
            })
        })
        .collect();

    let live_indices: Vec<usize> = f
        .accounts
        .iter()
        .enumerate()
        .filter(|(_, account)| {
            f.live_accounts
                .iter()
                .any(|live| live.slot == account.slot && live.pubkey == account.pubkey)
        })
        .map(|(i, _)| i)
        .collect();

    json!({
        "file_count": account_files.len(),
        "files": files,
        "count": f.accounts.len(),
        "live_count": f.live_accounts.len(),
        "live_indices": live_indices,
        "entries": entries,
    })
}
