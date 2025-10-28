# Policy for Data service
# Read access to database secrets only

path "secret/data/sentinel/*/database" {
  capabilities = ["read"]
}

path "secret/metadata/sentinel/*/database" {
  capabilities = ["read", "list"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
