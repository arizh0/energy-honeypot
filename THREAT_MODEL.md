# Threat Model

## Assets

- VPS host integrity and availability.
- Operator SSH access on port `2222`.
- Private raw logs, PCAPs, GeoIP databases, Terraform state, and `.env` secrets.
- Grafana and Loki analysis surfaces.
- Other internet hosts that must not be attacked from a compromised container.

## Exposed Attack Surface

The honeypot intentionally exposes:

- `22/tcp` and `23/tcp` through Cowrie.
- `80/tcp` and `443/tcp` through nginx to the Flask HelioControl interface.
- `1883/tcp` through the MQTT credential-capturing proxy.
- `502/tcp` through the Modbus proxy (forwarding to Conpot internally), `102/tcp` and `47808/udp` directly through Conpot.

Grafana and Loki have no published host ports. They live on the internal Docker monitoring network at fixed container IPs and are operator-only through SSH tunneling.

## Expected Attackers

Expected traffic includes commodity scanners, botnets, credential stuffers, opportunistic exploit attempts, MQTT probes, web scanners, and ICS protocol scanners. The system does not assume attackers are benign or careful.

## Controls

- **Network segmentation**: Two isolated Docker networks.
  - `honeypot` (`172.30.0.0/24`): all attacker-facing containers. The `DOCKER-USER` iptables chain blocks outbound internet access for this subnet so compromised containers cannot reach back to attacker infrastructure.
  - `monitoring` (`172.30.1.0/24`, `internal: true`): Loki, Grafana, and Promtail only. Docker removes the default gateway entirely, so these containers have no internet route at all. Honeypot containers cannot reach Loki or Grafana over the network; log delivery uses volume mounts and Docker's JSON-file log driver.
- All containers run with `no-new-privileges:true`, preventing privilege escalation via setuid binaries inside containers.
- All containers have memory and CPU limits, bounding the blast radius of a resource-exhaustion attempt.
- Health checks on all listening services allow Docker to detect silent failures.
- nginx is the only public entrypoint for the Flask app, so Flask trusts a single proxy hop.
- Grafana and Loki have no host port bindings and are not public.
- Raw captures and enriched logs are ignored by Git.

## Residual Risks

- A container escape could still compromise the VPS host.
- Incorrect host firewall rules could expose operator services or allow outbound abuse.
- Raw logs may contain sensitive third-party data.
- `cowrie` and `conpot` are pinned to image digests from the implementation date; they still require periodic vulnerability review and digest refresh.
- Conpot currently uses its default persona; richer energy-specific protocol behavior is future work.
