# Policy for Rust Core service
# Read access to broker secrets

path "secret/data/sentinel/*/broker" {
  capabilities = ["read"]
}

path "secret/metadata/sentinel/*/broker" {
  capabilities = ["read", "list"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
