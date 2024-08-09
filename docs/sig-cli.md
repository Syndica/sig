there are a few useful things to know when running a sig validator - while the full list 
of commands and options is available with the `--help` flag, this doc will better explain the importance of each option and when/when-not to use them (as well as constants
which you can change and recompile with)

there are a few important commands

## gossip

`sig gossip` is useful for running a gossip client to connect to the network 
and retrieve data. 

entrypoints (ie, first few nodes to ping / send pull requests) can be defined with the `-e` flag - this will usually be 
`entrypoint.mainnet-beta.solana.com:8001` or `entrypoint.testnet.solana.com:8001`
to start talking to the network

you wont need to change any of the defaults unless you are doing something specical 
requiring a different host or port.

we dont have a way to access the gossip data stored yet.

we do have many helpful metrics stored in a grafana dashboard while gossip runs which 
you can read me about in `prometheus-grafana/`

## snapshot-download

to load accountsdb, you first need to download a snapshot of the state on the network. 
to do this you can use the `sig snapshot-download` command. 

downloading a snapshot uses gossip to find peers to download from, you will still need to provide entrypoints
using the `-e` command. 

*note:* for testing/experiment purposes you should probably only download from testnet (7GB compressed), mainnet snapshots are very expensive to download + load (32GB compressed)

using the `-s` command you can change to where the snapshot is downloaded. 

if you cant find a fast enough peer to download from (default is *at least* 20MB/s) you 
can reduce the min download speed using the flag `--min-snapshot-download-speed`. 

The download speed can vary over time too, you can change `DOWNLOAD_PROGRESS_UPDATES_NS` 
(in `src/accountsdb/download.zig`) to wait longer before it checks if the peer is fast enough 
(default waits 30seconds).

## snapshot-validate / loading accountsdb from a snapshot

loading/validating from can be tricky due to the number of accounts required to load 

the `-s` flag you can point to where the snapshot is
- the code looks for a file with `.tar.zst` extension to startup from 
- if there is an `accounts/` directory, it will skip decompressing/unarchiving and 
load directly from the account files in `accounts/`
    - you can force a fresh unpack if you use the `-f` flag

if you are running OOM when loading, its likely you dont have enough RAM to generate the 
account index. you can use disk memory to back the index using `--use-disk-index` and reduce the ram requirements.

#### a note on genesis files

genesis files are typically downloaded as `.tar.bzip` - there isnt much support for bzip in zig (and the C code wasnt easy to port to zig) - because the genesis files shouldnt change we predownloaded and unpacked
the genesis binaries for mainnet, testnet, and devnet in `genesis-files/`. 

you need to provide a path to the matching genesis file of the snapshot you downloaded
to complete the verification using the `-g` command. 

for example, if you download a testnet snapshot and want to run verification, you 
need to run `./zig-out/bin/sig snapshot-validate -s ../testnet-snapshots/ -g genesis-files/testnet-genesis.bin`

## validator

the `sig validator` command is something we are building out overtime to start a full validator.

right now we support 
- starting gossip 
- downloading or loading from a snapshot 
- computing the leaderschedule from a snapshot
- collecting shreds from the network

most of the important options have been described in the above commands