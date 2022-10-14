# UNDER CONSTRUCTION

# Integrate GitLab with Conjur Enterprise using the JWT authenticator

## Introduction

[PLACEHOLDER]

## How does GitLab integration with Conjur using JWT work?

[PLACEHOLDER]

- Example JWT

```console
{
  "namespace_id": "2",
  "namespace_path": "cybr",
  "project_id": "2",
  "project_path": "cybr/aws-access-key-demo",
  "user_id": "1",
  "user_login": "root",
  "user_email": "joe.tan@cyberark.com",
  "pipeline_id": "2",
  "pipeline_source": "push",
  "job_id": "6",
  "ref": "main",
  "ref_type": "branch",
  "ref_protected": "true",
  "jti": "e8c142e7-fbc3-437f-a6c1-4aeccf6de6b4",
  "iss": "https://gitlab.vx",
  "iat": 1665704185,
  "nbf": 1665704180,
  "exp": 1665707785,
  "sub": "project_path:cybr/aws-access-key-demo:ref_type:branch:ref:main",
  "aud": "https://gitlab.vx"
}
```

# Conjur policies for GitLab JWT

## Load the Conjur policies and prepare Conjur for GitLab JWT

- Login to Conjur

```console
conjur init -u https://conjur.vx
conjur login -i admin -p CyberArk123!
```

- Download and load the Conjur policies

```console
curl -O https://raw.githubusercontent.com/joetanx/conjur-gitlab/main/authn-jwt.yaml
curl -O https://raw.githubusercontent.com/joetanx/conjur-gitlab/main/authn-jwt-hosts.yaml
conjur policy load -b root -f authn-jwt.yaml && rm -f authn-jwt.yaml
conjur policy load -b root -f authn-jwt-hosts.yaml && rm -f authn-jwt-hosts.yaml
```

- Enable the JWT Authenticator

```console
podman exec conjur sed -i -e '$aCONJUR_AUTHENTICATORS="authn,authn-jwt/gitlab"' /opt/conjur/etc/conjur.conf
podman exec conjur sv restart conjur
```

- Populate the variables
- Assumes that the secret variables in `world_db` and `aws_api` are already populated in step 2 (Setup Conjur master)

```console
conjur variable set -i conjur/authn-jwt/gitlab/jwks-uri -v https://gitlab.vx/-/jwks/
conjur variable set -i conjur/authn-jwt/gitlab/token-app-property -v project_path
conjur variable set -i conjur/authn-jwt/gitlab/identity-path -v jwt-apps/gitlab
conjur variable set -i conjur/authn-jwt/gitlab/issuer -v https://gitlab.vx
```

- Clean-up

```console
rm -f *.yaml
```
