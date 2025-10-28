# Policy for Authentication service
# Full access to auth secrets, read access to database

path "secret/data/sentinel/*/auth" {
  capabilities = ["read", "list"]
}

path "secret/data/sentinel/*/database" {
  capabilities = ["read"]
}

path "secret/metadata/sentinel/*" {
  capabilities = ["read", "list"]
}

# Allow token operations
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
