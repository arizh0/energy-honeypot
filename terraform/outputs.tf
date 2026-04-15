output "server_ip" {
  value       = contabo_instance.honeypot.ip_config[0].v4[0].ip
  description = "Public IP of the honeypot VPS"
}

output "instance_id" {
  value       = contabo_instance.honeypot.id
  description = "Contabo instance ID"
}