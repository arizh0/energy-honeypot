# Ethics And Operating Rules

This honeypot is for defensive research on infrastructure you own or are explicitly authorized to operate. It is intentionally exposed to unsolicited internet traffic and must never be used to lure traffic through deception on networks where you do not have permission.

## Boundaries

- Do not retaliate, scan back, exploit, or contact systems that interact with the honeypot.
- Do not attempt to identify individuals behind source IP addresses.
- Do not reuse captured credentials against any real service.
- Do not redistribute raw logs or payloads unless they have been reviewed and sanitized.

## Containment

- Honeypot containers must not have unrestricted outbound internet access.
- Operator services such as Grafana and Loki must remain localhost-only, VPN-only, or SSH-tunnel-only.
- Real SSH administration must run on a non-honeypot port before Cowrie is exposed on port `22`.

## Data Handling

Raw logs may include source IPs, attempted usernames/passwords, MQTT credentials, request metadata, payload snippets, uploaded firmware filenames, and firmware hashes. Keep raw logs private and out of Git.

Recommended retention:

- Keep raw VPS logs only as long as needed for analysis.
- Keep derived reports and anonymized summaries for publication or coursework.
- Delete payloads and PCAPs that are not needed for a concrete research question.
