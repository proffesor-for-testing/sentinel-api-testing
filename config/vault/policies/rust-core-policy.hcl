# Rust Core Service Policy
# Allows reading rust core secrets and swarm configuration

path "secret/data/sentinel/*/rust-core/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/swarm/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/database/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/shared/*" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
