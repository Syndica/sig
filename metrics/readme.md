# Metrics

Metrics include prometheus, grafana, loki, and alloy.

The main folder is in `src/metrics/`.

## Setup

- install `docker compose`
- macos or linux (windows untested/unsupported)

## Running

- change directory into `src/metrics/`
- `docker compose up -d`

## Shutting down

- change directory into `src/metrics/`
- `docker compose down`

## Info

- Grafana will be accessable on `localhost:3000`
  - note: `username: admin` and `password: grafana`
- Prometheus will be accessable on `localhost:9090`
- Sig metrics will be published to `localhost:12345` (which are scraped by prometheus)

*Note:* To enable profiling, optionally supply SIG_PID `e.g. SIG_PID=$(pgrep sig) docker compose up -d`

*Note:* If you modify the sig metrics port through the cli, you will
need to also modify the prometheus `target` to point to the different port.

## Project Structure

```
.
├── docker-compose.yml
├── alloy/ -- this scrapes logs/ and pushes to loki
├── loki/ -- log database
├── grafana/
│   └── dashboards/ -- this is where the sig dashboard lives (will need to copy .json export of dashboard from running container and push through git for any dashboard changes)
│   └── datasources/ -- this points to prometheus docker
├── prometheus/
│   └── prometheus.yml
└── README.md
```

## Run with logs

To collect logs of the running sig client (which can then be viewed in
Grafana), run the following command:

`./zig-out/bin/sig gossip -n testnet 2>&1 | tee -a logs/sig.log`

This will pipe the logs to `logs/sig.log` and also display them in the terminal.

## Setting up Alerts

We also support alerts through grafana when running with logs (ie, send a
slack message on each error message). To enable this, set the slack
webhook url env variable in a `metrics/.env` file:

```
SLACK_WEBHOOK_URL=hooks.slack.com/services/AAA/BBB/CCC
```

This env variable is then propogated to the grafana container.

## Expected result

```
$ docker ps
CONTAINER ID   IMAGE                  COMMAND                  CREATED          STATUS         PORTS                                       NAMES
948f31ee975a   prom/prometheus        "/bin/prometheus --c…"   32 seconds ago   Up 3 seconds   0.0.0.0:9090->9090/tcp, :::9090->9090/tcp   prometheus
adc6fb731842   grafana/grafana        "/run.sh"                32 seconds ago   Up 3 seconds   0.0.0.0:3000->3000/tcp, :::3000->3000/tcp   grafana
e698bc98a061   grafana/alloy:v1.3.1   "/bin/alloy run --se…"   32 seconds ago   Up 3 seconds   0.0.0.0:3200->3200/tcp, :::3200->3200/tcp   alloy
f774e615e5b1   grafana/loki:3.0.0     "/usr/bin/loki --con…"   32 seconds ago   Up 3 seconds   0.0.0.0:3100->3100/tcp, :::3100->3100/tcp   loki
27ee173b0491   prom/node-exporter     "/bin/node_exporter"     32 seconds ago   Up 3 seconds   0.0.0.0:9100->9100/tcp, :::9100->9100/tcp   node-exporter
```
