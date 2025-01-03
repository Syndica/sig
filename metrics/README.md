original src: https://github.com/docker/awesome-compose/tree/master/prometheus-grafana

## Setup

requirements:

- `docker compose`
  - [https://docs.docker.com/engine/install/ubuntu/](https://docs.docker.com/engine/install/ubuntu/)
- macos or linux (windows untested/unsupported)

## Running

mac: `docker compose up -d`
linux: `docker compose up -d`

- grafana will be accessable on `localhost:3000`
  - note: `username: admin password: grafana`
- prometheus will be accessable on `localhost:9090`
- sig metrics will be published to localhost:12345 (if you change this on the sig cli, you will
  need to also modify the prometheus `target` to point to the different port).

## Shutting down

mac: `docker compose down`
linux: `docker compose down`

## Project Structure

```
.
├── docker-compose.yml
├── alloy -- this scrapes logs/ and pushes to loki
├── loki -- log database
├── grafana
│   └── dashboards/ -- this is where the sig dashboard lives (will need to copy .json export of dashboard from running container and push through git for any dashboard changes)
│   └── datasources/ -- this points to prometheus docker
├── prometheus
│   └── prometheus.yml
└── README.md
```

## Run with logs

`./zig-out/bin/sig gossip -n testnet 2>&1 | tee -a logs/sig.log`

## Setting up Alerts

Set the slack webhook url env variable in `/metrics/.env` file.

```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

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
