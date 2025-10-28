# Spec Service Policy
# Allows reading spec service secrets and LLM API keys

path "secret/data/sentinel/*/spec/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/llm/*" {
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
