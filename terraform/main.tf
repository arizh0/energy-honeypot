provider "contabo" {
  oauth2_client_id     = var.contabo_client_id
  oauth2_client_secret = var.contabo_client_secret
  oauth2_user          = var.contabo_username
  oauth2_pass          = var.contabo_password
}

# SSH key
resource "contabo_secret" "honeypot" {
  name  = "honeypot-key"
  type  = "ssh"
  value = file(var.ssh_public_key_path)
}

# VPS Instance
resource "contabo_instance" "honeypot" {
  display_name = "energy-honeypot"
  product_id   = var.product_id
  image_id     = var.image_id
  region       = var.region
  ssh_keys     = [contabo_secret.honeypot.id]

  user_data = <<-EOP
#cloud-config
package_update: true
packages:
  - docker.io
  - docker-compose-v2
  - tcpdump
  - jq
  - fail2ban
  - ufw
write_files:
  - path: /usr/local/sbin/honeypot-iptables-rules.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail

      DOCKER_SUBNET="$${DOCKER_SUBNET:-172.30.0.0/24}"

      iptables -N DOCKER-USER 2>/dev/null || true

      ensure_insert_rule() {
        local position="$1"
        shift
        if ! iptables -C DOCKER-USER "$@" 2>/dev/null; then
          iptables -I DOCKER-USER "$position" "$@"
        fi
      }

      ensure_append_rule() {
        if ! iptables -C DOCKER-USER "$@" 2>/dev/null; then
          iptables -A DOCKER-USER "$@"
        fi
      }

      ensure_insert_rule 1 -s "$DOCKER_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
      ensure_insert_rule 2 -s "$DOCKER_SUBNET" -d "$DOCKER_SUBNET" -j RETURN
      ensure_append_rule -s "$DOCKER_SUBNET" -j DROP
  - path: /etc/systemd/system/honeypot-firewall.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Apply honeypot Docker egress firewall rules
      After=docker.service
      Requires=docker.service

      [Service]
      Type=oneshot
      Environment=DOCKER_SUBNET=172.30.0.0/24
      ExecStart=/usr/local/sbin/honeypot-iptables-rules.sh
      RemainAfterExit=yes

      [Install]
      WantedBy=multi-user.target
runcmd:
  - systemctl enable docker
  - systemctl start docker
  - usermod -aG docker root
  - systemctl enable fail2ban
  - systemctl start fail2ban
  - mkdir -p /opt/honeypot/pcap
  # Disable password auth — cloud-init re-enables it in 50-cloud-init.conf; override it.
  - sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/50-cloud-init.conf
  - systemctl reload ssh
  # Wait for Docker to fully start so DOCKER-USER chain exists
  - until docker info >/dev/null 2>&1; do sleep 1; done
  - systemctl daemon-reload
  - systemctl enable --now honeypot-firewall.service
EOP
}
