variable "project_id" {
  description = "GCP project that holds the whole lab"
  type        = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "cluster_name" {
  type    = string
  default = "opswarden"
}

variable "node_count" {
  description = "Nodes in the primary GKE pool. Set to 0 with `make down` to stop paying for compute."
  type        = number
  default     = 3
}

variable "node_machine_type" {
  type    = string
  default = "e2-standard-2"
}

variable "spot_nodes" {
  description = "Use Spot VMs for the GKE node pool (cheaper, preemptible). Keep false on demo day."
  type        = bool
  default     = false
}

variable "master_authorized_cidrs" {
  description = "CIDRs allowed to reach the GKE API server public endpoint (e.g. your laptop /32)"
  type        = list(string)
}

variable "app_server_machine_type" {
  type    = string
  default = "e2-small"
}

variable "ssh_public_key" {
  description = "Optional OpenSSH public key installed for user 'ansible' on the app servers"
  type        = string
  default     = ""
}
