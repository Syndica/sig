//! Emit a small, self-consistent Solana snapshot with every field populated,
//! for use as a test fixture. Wire-format serialization goes through agave's
//! `serialize_bank_snapshot_into`.
//!
//! Usage: snapshot-generator PATH_PREFIX
//!
//! Also writes a JSON summary of every synthesized value.

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use serde_json::{json, Value};
use solana_account::ReadableAccount;
use solana_accounts_db::{account_storage_entry::AccountStorageEntry, accounts_file::AccountsFile};
use solana_clock::Slot;
use solana_runtime::{
    bank::{BankFieldsToSerialize, BankHashStats},
    serde_snapshot::{serialize_bank_snapshot_into, ExtraFieldsToSerialize},
};

use fixture::Account;

pub struct AccountFile {
    pub slot: Slot,
    pub id: u32,
    pub bytes: Vec<u8>,
}

mod fixture;
mod json;

const SLOT: Slot = 100;
const ACCOUNT_HEADER_SIZE: usize = 136;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        eprintln!("usage: snapshot-generator PREFIX");
        std::process::exit(2);
    }
    let prefix = &args[0];
    if prefix == "-h" || prefix == "--help" {
        eprintln!("usage: snapshot-generator PREFIX");
        std::process::exit(0);
    }

    run(prefix)
}

fn run(prefix: &str) -> std::io::Result<()> {
    let tar_dst = PathBuf::from(format!("{prefix}.tar.zst"));
    let json_dst = PathBuf::from(format!("{prefix}.json"));
    let slot = SLOT;

    let tmp = tempdir_new()?;
    let manifest_path = tmp.join("manifest");

    let (fixture, bank_fields, extra_fields) = fixture::build_fixture(slot);
    let (status_cache_bytes, status_cache_json) = build_status_cache(slot);

    let account_files = build_account_files(&fixture.accounts);
    for file in &account_files {
        std::fs::write(account_file_path(file, &tmp), &file.bytes)?;
    }

    // BankFieldsToSerialize / ExtraFieldsToSerialize aren't Clone, so build
    // the JSON before handing them to the serializer.
    let fixture_json = json::fixture_json_string(
        &fixture,
        &bank_fields,
        &extra_fields,
        status_cache_json,
        &account_files,
    );

    serialize_manifest(
        &manifest_path,
        bank_fields,
        extra_fields,
        &tmp,
        &account_files,
        &fixture.live_accounts,
    )?;
    let manifest_bytes = std::fs::read(&manifest_path)?;

    let tar_path = tmp.join("out.tar");
    build_tar(
        &tar_path,
        slot,
        &manifest_bytes,
        &status_cache_bytes,
        &account_files,
    )?;
    compress_zstd(&tar_path, &tar_dst)?;
    std::fs::write(&json_dst, fixture_json)?;

    let tar_size = std::fs::metadata(&tar_dst)?.len();
    let json_size = std::fs::metadata(&json_dst)?.len();
    eprintln!("wrote {} ({} bytes)", tar_dst.display(), tar_size);
    eprintln!("wrote {} ({} bytes)", json_dst.display(), json_size);

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

fn tempdir_new() -> std::io::Result<PathBuf> {
    let mut p = std::env::temp_dir();
    p.push(format!("snapshot-generator.{}", std::process::id()));
    if p.exists() {
        std::fs::remove_dir_all(&p)?;
    }
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

fn build_account_files(accounts: &[Account]) -> Vec<AccountFile> {
    let mut slots: Vec<_> = accounts.iter().map(|a| a.slot).collect();
    slots.sort();
    slots.dedup();

    slots
        .into_iter()
        .enumerate()
        .map(|(i, slot)| {
            let mut bytes = Vec::new();
            for account in accounts.iter().filter(|a| a.slot == slot) {
                // AppendVec on-disk format, agave/accounts-db/src/accounts_file/meta.rs.
                let start = bytes.len();
                let data = account.account.data();
                bytes.extend_from_slice(&0u64.to_le_bytes()); // write_version_obsolete
                bytes.extend_from_slice(&(data.len() as u64).to_le_bytes()); // data_len
                bytes.extend_from_slice(account.pubkey.as_ref());
                bytes.extend_from_slice(&account.account.lamports().to_le_bytes());
                bytes.extend_from_slice(&account.account.rent_epoch().to_le_bytes());
                bytes.extend_from_slice(account.account.owner().as_ref());
                bytes.push(account.account.executable() as u8);
                bytes.extend_from_slice(&[0u8; 7]); // padding to align hash
                bytes.extend_from_slice(&[0u8; 32]); // hash (must be zero, agave >=v3)
                assert_eq!(bytes.len() - start, ACCOUNT_HEADER_SIZE);
                bytes.extend_from_slice(data);
                while !bytes.len().is_multiple_of(8) {
                    bytes.push(0); // 8-byte alignment for the next entry
                }
            }
            AccountFile {
                slot,
                id: (i + 1) as u32,
                bytes,
            }
        })
        .collect()
}

fn account_file_path(file: &AccountFile, dir: &Path) -> PathBuf {
    dir.join(format!("{}.{}", file.slot, file.id))
}

pub fn slot_history_found_slots(slot: Slot) -> Vec<Slot> {
    vec![0, slot.saturating_sub(1), slot]
}

fn serialize_manifest(
    dst: &Path,
    bank_fields: BankFieldsToSerialize,
    extra_fields: ExtraFieldsToSerialize,
    account_dir: &Path,
    account_files: &[AccountFile],
    live_accounts: &[Account],
) -> std::io::Result<()> {
    let mut storage = Vec::new();
    for file in account_files {
        let file_info = agave_fs::FileInfo::new_from_path(account_file_path(file, account_dir))?;
        let accounts_file = AccountsFile::new_for_startup(file_info)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        storage.push(Arc::new(AccountStorageEntry::new_existing(
            file.slot,
            file.id,
            accounts_file,
            Default::default(),
        )));
    }

    let mut bank_hash_stats = BankHashStats {
        num_updated_accounts: 0,
        num_removed_accounts: 0,
        num_lamports_stored: 0,
        total_data_len: 0,
        num_executable_accounts: 0,
    };
    for a in live_accounts {
        bank_hash_stats.update(&a.account);
    }
    let mut w = BufWriter::new(File::create(dst)?);
    serialize_bank_snapshot_into(&mut w, bank_fields, bank_hash_stats, &storage, extra_fields)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    w.flush()
}

fn build_status_cache(slot: Slot) -> (Vec<u8>, Value) {
    // Wire format: Vec<(Slot, bool, HashMap<Hash, (usize, Vec<(KeySlice, Result<(), TxErr>)>)>)>.
    // Three slot deltas, each with one blockhash bucket holding one Ok and one
    // Err(InstructionError(_, Custom(_))).

    let mut buf = Vec::new();
    buf.extend_from_slice(&3u64.to_le_bytes()); // outer Vec len
    let mut slot_deltas = Vec::new();
    for (index, (delta_slot, is_root)) in [(slot, true), (slot.saturating_sub(1), true), (0, true)]
        .into_iter()
        .enumerate()
    {
        let tag = index as u8;
        let blockhash = [0xAA + tag; 32];
        let ok_key = [0x10 + tag; 20];
        let err_key = [0x20 + tag; 20];
        let fork_count = 2 + index as u64;
        let instruction_index = 3 + tag;
        let custom_code = 9 + index as u32;

        buf.extend_from_slice(&delta_slot.to_le_bytes());
        buf.push(is_root as u8);
        buf.extend_from_slice(&1u64.to_le_bytes()); // HashMap len = 1
        buf.extend_from_slice(&blockhash);
        buf.extend_from_slice(&fork_count.to_le_bytes());
        buf.extend_from_slice(&2u64.to_le_bytes()); // inner Vec len = 2

        // Ok entry.
        buf.extend_from_slice(&ok_key);
        buf.extend_from_slice(&0u32.to_le_bytes()); // Ok tag

        // Err(InstructionError(3, Custom(9))) entry.
        buf.extend_from_slice(&err_key);
        buf.extend_from_slice(&1u32.to_le_bytes()); // Err tag
        buf.extend_from_slice(&8u32.to_le_bytes()); // TxErr::InstructionError
        buf.push(instruction_index);
        buf.extend_from_slice(&25u32.to_le_bytes()); // InstructionError::Custom
        buf.extend_from_slice(&custom_code.to_le_bytes());

        slot_deltas.push(json!({
            "index": index,
            "slot": delta_slot,
            "is_root": is_root,
            "buckets": [{
                "index": 0,
                "blockhash_hex": json::hex_line(&blockhash),
                "fork_count": fork_count,
                "entries": [
                    {
                        "key_slice_hex": json::hex_line(&ok_key),
                        "result": {"type": "Ok"},
                    },
                    {
                        "key_slice_hex": json::hex_line(&err_key),
                        "result": {
                            "type": "Err",
                            "transaction_error": {
                                "type": "InstructionError",
                                "instruction_index": instruction_index,
                                "instruction_error": {"type": "Custom", "custom_code": custom_code},
                            },
                        },
                    },
                ],
            }],
        }));
    }
    let json = json!({
        "on_disk_size": buf.len(),
        "slot_deltas_count": slot_deltas.len(),
        "slot_deltas": slot_deltas,
    });
    (buf, json)
}

fn build_tar(
    dst: &Path,
    slot: Slot,
    manifest: &[u8],
    status_cache: &[u8],
    account_files: &[AccountFile],
) -> std::io::Result<()> {
    fn tar_file<W: Write>(
        ar: &mut tar::Builder<W>,
        name: &str,
        data: &[u8],
    ) -> std::io::Result<()> {
        let mut h = tar::Header::new_ustar();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        ar.append_data(&mut h, name, data)
    }
    fn tar_dir<W: Write>(ar: &mut tar::Builder<W>, name: &str) -> std::io::Result<()> {
        let mut h = tar::Header::new_ustar();
        h.set_size(0);
        h.set_mode(0o755);
        h.set_entry_type(tar::EntryType::Directory);
        h.set_cksum();
        ar.append_data(&mut h, name, std::io::empty())
    }

    let mut ar = tar::Builder::new(BufWriter::new(File::create(dst)?));
    ar.mode(tar::HeaderMode::Deterministic);
    tar_file(&mut ar, "version", b"1.2.0")?;
    tar_dir(&mut ar, "snapshots/")?;
    tar_file(&mut ar, "snapshots/status_cache", status_cache)?;
    tar_dir(&mut ar, &format!("snapshots/{slot}/"))?;
    tar_file(&mut ar, &format!("snapshots/{slot}/{slot}"), manifest)?;
    tar_dir(&mut ar, "accounts/")?;
    for file in account_files {
        tar_file(
            &mut ar,
            &format!("accounts/{}.{}", file.slot, file.id),
            &file.bytes,
        )?;
    }
    ar.into_inner()?.flush()
}

fn compress_zstd(src: &Path, dst: &Path) -> std::io::Result<()> {
    let status = Command::new("zstd")
        .args(["-q", "-f", "-19", "-o"])
        .arg(dst)
        .arg(src)
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!("zstd exited with {status}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        agave_snapshots::{
            snapshot_archive_info::SnapshotArchiveInfoGetter, snapshot_config::SnapshotConfig,
            snapshot_hash::SnapshotHash,
        },
        solana_accounts_db::accounts_db::ACCOUNTS_DB_CONFIG_FOR_TESTING,
        solana_epoch_schedule::EpochSchedule,
        solana_fee_calculator::FeeRateGovernor,
        solana_genesis_config::GenesisConfig,
        solana_inflation::Inflation,
        solana_pubkey::Pubkey,
        solana_runtime::{runtime_config::RuntimeConfig, snapshot_bank_utils},
        std::{
            collections::HashSet,
            str::FromStr,
            sync::{atomic::AtomicBool, Arc},
        },
    };

    #[test]
    fn agave_loads_and_verifies_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let archives_dir = temp.path().join("archives");
        let incremental_dir = temp.path().join("incremental");
        let bank_snapshots_dir = temp.path().join("bank_snapshots");
        let accounts_dir = temp.path().join("accounts");
        std::fs::create_dir_all(&archives_dir).unwrap();
        std::fs::create_dir_all(&incremental_dir).unwrap();
        std::fs::create_dir_all(&bank_snapshots_dir).unwrap();
        std::fs::create_dir_all(&accounts_dir).unwrap();

        let (_, bank_fields, _) = fixture::build_fixture(SLOT);
        let snapshot_hash = SnapshotHash::new(bank_fields.accounts_lt_hash.0.checksum());
        let prefix = archives_dir.join(format!("snapshot-{SLOT}-{}", snapshot_hash.0));
        run(prefix.to_str().unwrap()).unwrap();

        let mut snapshot_config = SnapshotConfig::new_load_only();
        snapshot_config.full_snapshot_archives_dir = archives_dir;
        snapshot_config.incremental_snapshot_archives_dir = incremental_dir;
        snapshot_config.bank_snapshots_dir = bank_snapshots_dir;
        snapshot_config.use_direct_io = false;
        snapshot_config.use_registered_io_uring_buffers = false;

        let genesis_config = GenesisConfig {
            creation_time: 1_700_000_000,
            ticks_per_slot: fixture::TICKS_PER_SLOT,
            fee_rate_governor: FeeRateGovernor::new(5_000, 1),
            epoch_schedule: EpochSchedule::default(),
            inflation: Inflation::default(),
            ..GenesisConfig::default()
        };

        let exit = Arc::new(AtomicBool::new(false));
        let (bank, full_snapshot, incremental_snapshot) =
            snapshot_bank_utils::bank_from_latest_snapshot_archives(
                &[accounts_dir],
                &snapshot_config,
                &genesis_config,
                &RuntimeConfig::default(),
                None,
                None,
                true,
                false,
                false,
                ACCOUNTS_DB_CONFIG_FOR_TESTING,
                None,
                exit,
            )
            .unwrap();

        let json_path = PathBuf::from(format!("{}.json", prefix.to_str().unwrap()));
        let json: Value = serde_json::from_slice(&std::fs::read(json_path).unwrap()).unwrap();
        let merged = &json["merged_fields"];

        assert_eq!(bank.slot(), merged["slot"].as_u64().unwrap());
        assert_eq!(full_snapshot.slot(), merged["slot"].as_u64().unwrap());
        assert!(incremental_snapshot.is_none());
        assert_eq!(bank.epoch(), merged["epoch"].as_u64().unwrap());
        assert_eq!(bank.parent_slot(), merged["parent_slot"].as_u64().unwrap());
        assert_eq!(
            bank.block_height(),
            merged["block_height"].as_u64().unwrap()
        );
        assert_eq!(bank.hash().to_string(), merged["hash"].as_str().unwrap());
        assert_eq!(
            bank.parent_hash().to_string(),
            merged["parent_hash"].as_str().unwrap()
        );
        assert_eq!(
            bank.block_id().unwrap().to_string(),
            merged["block_id"].as_str().unwrap()
        );
        assert_eq!(
            bank.leader_id().to_string(),
            merged["leader_id"].as_str().unwrap()
        );
        assert_eq!(
            bank.transaction_count(),
            merged["transaction_count"].as_u64().unwrap()
        );
        assert_eq!(
            bank.signature_count(),
            merged["signature_count"].as_u64().unwrap()
        );
        assert_eq!(bank.tick_height(), merged["tick_height"].as_u64().unwrap());
        assert_eq!(
            bank.max_tick_height(),
            merged["max_tick_height"].as_u64().unwrap()
        );
        assert_eq!(
            bank.ticks_per_slot(),
            merged["ticks_per_slot"].as_u64().unwrap()
        );
        assert_eq!(
            bank.hashes_per_tick(),
            Some(merged["hashes_per_tick"].as_u64().unwrap())
        );
        assert_eq!(
            bank.capitalization(),
            merged["capitalization"].as_u64().unwrap()
        );
        assert_eq!(
            bank.load_accounts_data_size(),
            merged["accounts_data_len"].as_u64().unwrap()
        );

        let extra_fee = json["extra_fields"]["lamports_per_signature"]
            .as_u64()
            .unwrap();
        let merged_fee = merged["fee_rate_governor"]["lamports_per_signature"]
            .as_u64()
            .unwrap();
        let bank_field_fee = json["bank_fields"]["fee_rate_governor"]["lamports_per_signature"]
            .as_u64()
            .unwrap();
        assert_eq!(merged_fee, extra_fee);
        assert_eq!(merged_fee, bank.get_lamports_per_signature());
        if bank_field_fee != extra_fee {
            assert_ne!(merged_fee, bank_field_fee);
        }
        for hash in merged["blockhash_queue"]["hashes"].as_array().unwrap() {
            let blockhash_fee = hash["lamports_per_signature"].as_u64().unwrap();
            if blockhash_fee != extra_fee {
                assert_ne!(merged_fee, blockhash_fee);
            }
        }

        let merged_epochs: Vec<_> = merged["versioned_epoch_stakes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|epoch_stakes| epoch_stakes["epoch"].as_u64().unwrap())
            .collect();
        let mut bank_epochs: Vec<_> = bank.epoch_stakes_map().keys().copied().collect();
        bank_epochs.sort();
        assert_eq!(merged_epochs, bank_epochs);

        let slot_history = bank.get_slot_history().unwrap();
        let found_slots_from_bank: Vec<_> = (0..=bank.slot())
            .filter(|slot| slot_history.check(*slot) == solana_slot_history::Check::Found)
            .collect();
        let found_slots_from_json: Vec<_> = merged["slot_history_found_slots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|slot| slot.as_u64().unwrap())
            .collect();
        assert_eq!(found_slots_from_json, found_slots_from_bank);

        let accounts = &json["accounts"];
        let entries = accounts["entries"].as_array().unwrap();
        let live_indices: Vec<usize> = accounts["live_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|index| index.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(
            accounts["live_count"].as_u64().unwrap() as usize,
            live_indices.len()
        );

        let live_indices_set: HashSet<_> = live_indices.iter().copied().collect();
        for index in live_indices.iter().copied() {
            let entry = &entries[index];
            let pubkey = Pubkey::from_str(entry["pubkey"].as_str().unwrap()).unwrap();
            let (loaded_account, modified_slot) = bank.get_account_modified_slot(&pubkey).unwrap();
            assert_eq!(modified_slot, entry["slot"].as_u64().unwrap());
            assert_eq!(
                loaded_account.lamports(),
                entry["lamports"].as_u64().unwrap()
            );
            assert_eq!(
                loaded_account.owner().to_string(),
                entry["owner"].as_str().unwrap()
            );
            assert_eq!(
                loaded_account.executable(),
                entry["executable"].as_bool().unwrap()
            );
            assert_eq!(
                loaded_account.rent_epoch(),
                entry["rent_epoch"].as_u64().unwrap()
            );
            assert_eq!(
                loaded_account.data().len(),
                entry["data_len"].as_u64().unwrap() as usize
            );
            assert_eq!(
                json::hex_line(loaded_account.data()),
                entry["data_hex"].as_str().unwrap()
            );
        }

        for (index, entry) in entries.iter().enumerate() {
            if live_indices_set.contains(&index) {
                continue;
            }
            let stale_pubkey = entry["pubkey"].as_str().unwrap();
            let live_duplicate = live_indices
                .iter()
                .copied()
                .any(|live_index| entries[live_index]["pubkey"].as_str().unwrap() == stale_pubkey);
            if live_duplicate {
                let pubkey = Pubkey::from_str(stale_pubkey).unwrap();
                let (_, modified_slot) = bank.get_account_modified_slot(&pubkey).unwrap();
                assert_ne!(modified_slot, entry["slot"].as_u64().unwrap());
            }
        }
    }
}
