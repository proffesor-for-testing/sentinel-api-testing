# Policy for Orchestration service
# Read access to broker, LLM, and database secrets

path "secret/data/sentinel/*/broker" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/llm" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/database" {
  capabilities = ["read"]
}

path "secret/metadata/sentinel/*" {
  capabilities = ["read", "list"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
