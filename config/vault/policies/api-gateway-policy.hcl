# API Gateway Service Policy
# Allows reading API gateway secrets and shared configuration

path "secret/data/sentinel/*/api-gateway/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/shared/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/database/*" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
