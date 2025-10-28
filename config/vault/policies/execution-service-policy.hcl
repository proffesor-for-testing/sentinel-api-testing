# Execution Service Policy
# Allows reading execution service secrets

path "secret/data/sentinel/*/execution/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/rabbitmq/*" {
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
