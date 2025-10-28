# Policy for API Gateway service
# Read-only access to auth secrets for JWT validation

path "secret/data/sentinel/*/auth" {
  capabilities = ["read"]
}

path "secret/metadata/sentinel/*/auth" {
  capabilities = ["read"]
}

# Allow token renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token lookup
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
