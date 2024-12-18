original src: https://github.com/docker/awesome-compose/tree/master/prometheus-grafana

## Setup

requirements:
- `docker compose`
  - [https://docs.docker.com/engine/install/ubuntu/](https://docs.docker.com/engine/install/ubuntu/)
- either mac or linux supported

modify `/etc/hosts` to include the following line:
```
127.0.0.1 prometheus
127.0.0.1 loki
```

## Running

mac: `docker compose -f compose_mac.yaml up -d`
linux: `docker compose -f compose_linux.yaml up -d`

- grafana will be accessable on `localhost:3000`
  - note: `username: admin password: grafana`
- prometheus will be accessable on `localhost:9090`
- sig metrics will be published to localhost:12345 (if you change this on the sig cli, you will
need to also modify the prometheus `target` to point to the different port).

## Shutting down

mac: `docker compose -f compose_mac.yaml down`
linux: `docker compose -f compose_linux.yaml down`

## Compose sample
### Prometheus & Grafana

Project structure:
```
.
├── compose_linux.yaml
├── compose_mac.yaml
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

## Deploy with docker compose

```
$ docker compose up -d
Creating network "prometheus-grafana_default" with the default driver
Creating volume "prometheus-grafana_prom_data" with default driver
...
Creating grafana    ... done
Creating prometheus ... done
Attaching to prometheus, grafana

```

## Expected result

Listing containers must show two containers running and the port mapping as below:
```
$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                    NAMES
dbdec637814f        prom/prometheus     "/bin/prometheus --c…"   8 minutes ago       Up 8 minutes        0.0.0.0:9090->9090/tcp   prometheus
79f667cb7dc2        grafana/grafana     "/run.sh"                8 minutes ago       Up 8 minutes        0.0.0.0:3000->3000/tcp   grafana
```

Navigate to `http://localhost:3000` in your web browser and use the login credentials specified in the compose file to access Grafana. It is already configured with prometheus as the default datasource.

![page](output.jpg)

Navigate to `http://localhost:9090` in your web browser to access directly the web interface of prometheus.

Stop and remove the containers. Use `-v` to remove the volumes if looking to erase all data.
```
$ docker compose down -v
```
