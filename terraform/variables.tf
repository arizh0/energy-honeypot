variable "contabo_client_id" {
  description = "Contabo OAuth2 client ID (from my.contabo.com/api/details)"
  type        = string
  sensitive   = true
}

variable "contabo_client_secret" {
  description = "Contabo OAuth2 client secret"
  type        = string
  sensitive   = true
}

variable "contabo_username" {
  description = "Contabo account email address"
  type        = string
  sensitive   = true
}

variable "contabo_password" {
  description = "Contabo account password"
  type        = string
  sensitive   = true
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key file"
  type        = string
  default     = "~/.ssh/honeypot_ed25519.pub"
}

variable "region" {
  description = "Contabo datacenter region"
  type        = string
  default     = "UK"
}

variable "product_id" {
  description = "Contabo VPS product ID"
  type        = string
  default     = "V91"
}

variable "image_id" {
  description = "Contabo OS image UUID for Ubuntu 24.04. Look up with: cntb get images --output json | jq '.[] | select(.name==\"Ubuntu 24.04\")'"
  type        = string
  # Set this in terraform.tfvars — the UUID differs per region and changes with new releases
}
