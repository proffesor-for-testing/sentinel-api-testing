# Data Service Policy
# Allows reading data service secrets and external API keys

path "secret/data/sentinel/*/data/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/database/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/external-api/*" {
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
