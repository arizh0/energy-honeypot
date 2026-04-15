# energy-honeypot

This is a small energy-themed honeypot stack I use for internet-facing IoT/ICS research.

It pretends to be a solar inverter deployment: SSH and Telnet land in Cowrie, HTTP/HTTPS land on a fake HelioControl web UI, MQTT is proxied through a credential logger, and the ICS ports are handled by Conpot plus a small Modbus proxy. Logs go to Loki/Grafana on a private Docker network.

Do not run this on a network you do not own. It is meant for a disposable VPS or a lab host where you are allowed to receive unsolicited traffic.

## What Is Exposed

| Port | Service |
| --- | --- |
| `22/tcp` | Cowrie SSH |
| `23/tcp` | Cowrie Telnet |
| `80/tcp` | nginx to the Flask HelioControl UI |
| `443/tcp` | nginx TLS to the Flask HelioControl UI |
| `102/tcp` | Conpot S7Comm |
| `502/tcp` | Modbus proxy, forwarding to Conpot internally |
| `1883/tcp` | MQTT credential-capturing proxy |
| `47808/udp` | Conpot BACnet |

Grafana, Loki, Promtail, Mosquitto, and the Flask app have no published host ports. Grafana is reached through an SSH tunnel to the monitoring network, not by opening `3000` on the VPS.

## Before You Put It Online

If this repo is public while the honeypot is live, treat the default persona as fingerprintable. Change it before you rely on the data.

The obvious fingerprints are:

- HelioControl names, models, serials, page text, and firmware versions
- MQTT topics such as `solar/inverter/01/status`
- the Modbus device identity returned by `modbus-proxy`
- Cowrie MOTD and fake shell history
- the TLS certificate subject in `nginx/entrypoint.sh`
- the exact public port mix

None of those are secrets, but they do make the deployment easier to recognize if someone has read the repository.

## Containment

The attacker-facing containers sit on the `honeypot` Docker network. Host firewall rules in `firewall/iptables-rules.sh` use Docker's `DOCKER-USER` chain to block outbound internet access from that subnet while still allowing replies to inbound connections.

Monitoring is separate. Loki, Grafana, and Promtail sit on an `internal: true` Docker network. Docker gives that network no default gateway, and Compose publishes no monitoring ports on the host.

Real SSH should be moved away from port `22` before Cowrie is exposed. This setup assumes real SSH is on `2222` with key-only authentication.

## Deployment Notes

The stack is Docker Compose plus a small amount of host setup:

```bash
sudo install -m 0755 firewall/iptables-rules.sh /usr/local/sbin/honeypot-iptables-rules.sh
sudo install -m 0644 firewall/honeypot-firewall.service /etc/systemd/system/honeypot-firewall.service
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-firewall.service

sudo install -m 0755 scripts/conpot-watchdog.sh /usr/local/sbin/conpot-watchdog.sh
sudo install -m 0644 scripts/conpot-watchdog.service /etc/systemd/system/conpot-watchdog.service
sudo install -m 0644 scripts/conpot-watchdog.timer /etc/systemd/system/conpot-watchdog.timer
sudo systemctl daemon-reload
sudo systemctl enable --now conpot-watchdog.timer

GRAFANA_ADMIN_PASSWORD='<set-a-real-password>' docker compose up -d --build
```

Do not use `docker compose down -v` unless you mean to delete local container volumes.

Open Grafana through a tunnel:

```bash
ssh -L 3000:172.30.1.3:3000 -p 2222 admin@<vps-ip> -N
```

Then visit `http://localhost:3000`.

## Logs

Raw logs can contain source IPs, attempted credentials, HTTP request metadata, MQTT credentials, payload snippets, uploaded filenames, and file hashes.

Keep these private:

- `logs/`
- `geoip/*.mmdb`
- `.env`
- Terraform state and tfvars
- PCAPs and raw exports

The repository ignores those paths. The analysis scripts work on local exports and anonymised/enriched data, not on public raw logs.

## Useful Checks

Run these before publishing changes or redeploying:

```bash
python -m compileall flask-fallback modbus-proxy mqtt scripts analysis
python -m json.tool grafana-provisioning/dashboards/honeypot-overview.json
python -m unittest discover -s tests
GRAFANA_ADMIN_PASSWORD=dummy-for-config-check docker compose config
terraform -chdir=terraform fmt -check
terraform -chdir=terraform validate
```

After deployment, the public listeners should be `22`, `23`, `80`, `443`, `102`, `502`, `1883`, and `47808/udp`. Grafana and Loki should not appear as host listeners on `3000` or `3100`.
