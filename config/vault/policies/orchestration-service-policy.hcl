# Orchestration Service Policy
# Allows reading orchestration secrets and message broker credentials

path "secret/data/sentinel/*/orchestration/*" {
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
