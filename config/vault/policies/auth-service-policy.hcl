# Auth Service Policy
# Allows reading authentication and JWT secrets

path "secret/data/sentinel/*/auth/*" {
  capabilities = ["read"]
}

path "secret/data/sentinel/*/jwt/*" {
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
