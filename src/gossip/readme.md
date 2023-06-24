# Sig Gossip - Solana's gossip protocol

The Solana gossip protocol is a variation of the ["Minimum-Cost First-Push-Then-Pull Gossip" Algorithm](https://apps.dtic.mil/sti/trecms/pdf/AD1108603.pdf).

### `ClusterInfo::run_socket_consume` - Packets consumed from UdpSocket

This function is called and `spawn`ed and is a long running process. It's where all UDP packets are consumed into batches. Once consumed, they're deserialized into `Protocol` messages and pushed to the sender channel for processing.

### `ClusterInfo::run_listen` - Listens for Packet's to process

This function `spawn`ed and is a long running process. It listens to the packet receiver channel and then processes packets as they're pushed.
